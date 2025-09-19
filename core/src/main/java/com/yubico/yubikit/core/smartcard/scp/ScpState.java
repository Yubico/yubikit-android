/*
 * Copyright (C) 2024 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.core.smartcard.scp;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.ApduProcessor;
import com.yubico.yubikit.core.smartcard.ApduResponse;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.LoggerFactory;

/** Internal SCP state class for managing SCP state, handling encryption/decryption and MAC. */
public class ScpState {
  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(ScpState.class);

  private final SessionKeys keys;
  private byte[] macChain;
  private int encCounter = 1;

  public ScpState(SessionKeys keys, byte[] macChain) {
    this.keys = keys;
    this.macChain = macChain;
  }

  public @Nullable DataEncryptor getDataEncryptor() {
    if (keys.dek == null) {
      return null;
    }
    return data -> cbcEncrypt(keys.dek, data);
  }

  public byte[] encrypt(byte[] data) {
    // Pad the data
    Logger.trace(logger, "Plaintext data: {}", StringUtils.bytesToHex(data));
    int padLen = 16 - (data.length % 16);
    byte[] padded = Arrays.copyOf(data, data.length + padLen);
    padded[data.length] = (byte) 0x80;

    // Encrypt
    try {
      @SuppressWarnings("GetInstance")
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, keys.senc);
      byte[] ivData = ByteBuffer.allocate(16).put(new byte[12]).putInt(encCounter++).array();
      byte[] iv = cipher.doFinal(ivData);

      cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, keys.senc, new IvParameterSpec(iv));
      return cipher.doFinal(padded);
    } catch (InvalidKeyException
        | NoSuchPaddingException
        | NoSuchAlgorithmException
        | IllegalBlockSizeException
        | BadPaddingException
        | InvalidAlgorithmParameterException e) {
      // This should never happen
      throw new RuntimeException(e);
    } finally {
      Arrays.fill(padded, (byte) 0);
    }
  }

  public byte[] decrypt(byte[] encrypted) throws BadResponseException {
    // Decrypt
    byte[] decrypted = null;
    try {
      @SuppressWarnings("GetInstance")
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, keys.senc);
      byte[] ivData =
          ByteBuffer.allocate(16).put((byte) 0x80).put(new byte[11]).putInt(encCounter - 1).array();
      byte[] iv = cipher.doFinal(ivData);

      cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, keys.senc, new IvParameterSpec(iv));
      decrypted = cipher.doFinal(encrypted);
      for (int i = decrypted.length - 1; i > 0; i--) {
        if (decrypted[i] == (byte) 0x80) {
          Logger.trace(logger, "Plaintext resp: {}", StringUtils.bytesToHex(decrypted));
          return Arrays.copyOf(decrypted, i);
        } else if (decrypted[i] != 0x00) {
          break;
        }
      }
      throw new BadResponseException("Bad padding");
    } catch (InvalidKeyException
        | NoSuchPaddingException
        | NoSuchAlgorithmException
        | IllegalBlockSizeException
        | BadPaddingException
        | InvalidAlgorithmParameterException e) {
      // This should never happen
      throw new RuntimeException(e);
    } finally {
      if (decrypted != null) {
        Arrays.fill(decrypted, (byte) 0);
      }
    }
  }

  public byte[] mac(byte[] data) {
    try {
      Mac mac = Mac.getInstance("AESCMAC");
      mac.init(keys.smac);
      mac.update(macChain);
      macChain = mac.doFinal(data);
      return Arrays.copyOf(macChain, 8);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new UnsupportedOperationException("Cryptography provider does not support AESCMAC", e);
    }
  }

  public byte[] unmac(byte[] data, short sw) throws BadResponseException {
    byte[] msg =
        ByteBuffer.allocate(data.length - 8 + 2).put(data, 0, data.length - 8).putShort(sw).array();

    try {
      Mac mac = Mac.getInstance("AESCMAC");
      mac.init(keys.srmac);
      mac.update(macChain);

      byte[] rmac = Arrays.copyOf(mac.doFinal(msg), 8);
      if (MessageDigest.isEqual(rmac, Arrays.copyOfRange(data, data.length - 8, data.length))) {
        return Arrays.copyOf(msg, msg.length - 2);
      }
      throw new BadResponseException("Wrong MAC");
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new UnsupportedOperationException("Cryptography provider does not support AESCMAC", e);
    }
  }

  public static Pair<ScpState, byte[]> scp03Init(
      ApduProcessor processor, Scp03KeyParams keyParams, @Nullable byte[] hostChallenge)
      throws BadResponseException, IOException, ApduException {
    if (hostChallenge == null) {
      hostChallenge = RandomUtils.getRandomBytes(8);
    }

    ApduResponse resp =
        processor.sendApdu(
            new Apdu(
                0x80,
                SecurityDomainSession.INS_INITIALIZE_UPDATE,
                keyParams.getKeyRef().getKvn(),
                0x00,
                hostChallenge));
    if (resp.getSw() != SW.OK) {
      throw new ApduException(resp.getData(), resp.getSw());
    }

    byte[] diversificationData = new byte[10];
    byte[] keyInfo = new byte[3];
    byte[] cardChallenge = new byte[8];
    byte[] cardCryptogram = new byte[8];
    ByteBuffer.wrap(resp.getData())
        .get(diversificationData)
        .get(keyInfo)
        .get(cardChallenge)
        .get(cardCryptogram);

    byte[] context = ByteBuffer.allocate(16).put(hostChallenge).put(cardChallenge).array();
    SessionKeys sessionKeys = keyParams.keys.derive(context);

    byte[] genCardCryptogram =
        StaticKeys.deriveKey(sessionKeys.smac, (byte) 0x00, context, (byte) 0x40).getEncoded();
    if (!MessageDigest.isEqual(genCardCryptogram, cardCryptogram)) {
      throw new BadResponseException("Wrong SCP03 key set");
    }

    byte[] hostCryptogram =
        StaticKeys.deriveKey(sessionKeys.smac, (byte) 0x01, context, (byte) 0x40).getEncoded();
    return new Pair<>(new ScpState(sessionKeys, new byte[16]), hostCryptogram);
  }

  public static ScpState scp11Init(ApduProcessor processor, Scp11KeyParams keyParams)
      throws BadResponseException, IOException, ApduException {
    // GPC v2.3 Amendment F (SCP11) v1.4 §7.1.1
    byte params;
    byte kid = keyParams.getKeyRef().getKid();
    switch (kid) {
      case ScpKid.SCP11a:
        params = 0b01;
        break;
      case ScpKid.SCP11b:
        params = 0b00;
        break;
      case ScpKid.SCP11c:
        params = 0b11;
        break;
      default:
        throw new IllegalArgumentException("Invalid SCP11 KID");
    }

    if (kid == ScpKid.SCP11a || kid == ScpKid.SCP11c) {
      // GPC v2.3 Amendment F (SCP11) v1.4 §7.5
      Objects.requireNonNull(keyParams.skOceEcka);
      int n = keyParams.certificates.size() - 1;
      if (n < 0) {
        throw new IllegalArgumentException("SCP11a and SCP11c require a certificate chain");
      }
      KeyRef oceRef =
          keyParams.oceKeyRef != null ? keyParams.oceKeyRef : new KeyRef((byte) 0, (byte) 0);
      for (int i = 0; i <= n; i++) {
        try {
          byte[] data = keyParams.certificates.get(i).getEncoded();
          byte p2 = (byte) (oceRef.getKid() | (i < n ? 0x80 : 0x00));
          ApduResponse resp =
              processor.sendApdu(
                  new Apdu(
                      0x80,
                      SecurityDomainSession.INS_PERFORM_SECURITY_OPERATION,
                      oceRef.getKvn(),
                      p2,
                      data));
          if (resp.getSw() != SW.OK) {
            throw new ApduException(resp.getData(), resp.getSw());
          }
        } catch (CertificateEncodingException e) {
          throw new IllegalArgumentException("Invalid certificate encoding", e);
        }
      }
    }

    byte[] keyUsage =
        new byte[] {0x3C}; // AUTHENTICATED | C_MAC | C_DECRYPTION | R_MAC | R_ENCRYPTION
    byte[] keyType = new byte[] {(byte) 0x88}; // AES
    byte[] keyLen = new byte[] {16}; // 128-bit

    // Host ephemeral key
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      ECPublicKey pk = (ECPublicKey) keyParams.pkSdEcka;
      kpg.initialize(pk.getParams());
      KeyPair ephemeralOceEcka = kpg.generateKeyPair();
      PublicKeyValues.Ec epkOceEcka =
          (PublicKeyValues.Ec) PublicKeyValues.fromPublicKey(ephemeralOceEcka.getPublic());

      // GPC v2.3 Amendment F (SCP11) v1.4 §7.6.2.3
      byte[] data =
          Tlvs.encodeList(
              Arrays.asList(
                  new Tlv(
                      0xA6,
                      Tlvs.encodeList(
                          Arrays.asList(
                              new Tlv(0x90, new byte[] {0x11, params}),
                              new Tlv(0x95, keyUsage),
                              new Tlv(0x80, keyType),
                              new Tlv(0x81, keyLen)))),
                  new Tlv(0x5F49, epkOceEcka.getEncodedPoint())));

      // Static host key (SCP11a/c), or ephemeral key again (SCP11b)
      PrivateKey skOceEcka =
          keyParams.skOceEcka != null ? keyParams.skOceEcka : ephemeralOceEcka.getPrivate();
      int ins =
          keyParams.getKeyRef().getKid() == ScpKid.SCP11b
              ? SecurityDomainSession.INS_INTERNAL_AUTHENTICATE
              : SecurityDomainSession.INS_EXTERNAL_AUTHENTICATE;
      ApduResponse resp =
          processor.sendApdu(
              new Apdu(
                  0x80, ins, keyParams.getKeyRef().getKvn(), keyParams.getKeyRef().getKid(), data));
      if (resp.getSw() != SW.OK) {
        throw new ApduException(resp.getData(), resp.getSw());
      }
      List<Tlv> tlvs = Tlvs.decodeList(resp.getData());
      Tlv epkSdEckaTlv = tlvs.get(0);
      byte[] epkSdEckaEncodedPoint = Tlvs.unpackValue(0x5F49, epkSdEckaTlv.getBytes());
      byte[] receipt = Tlvs.unpackValue(0x86, tlvs.get(1).getBytes());

      // GPC v2.3 Amendment F (SCP11) v1.3 §3.1.2 Key Derivation
      byte[] keyAgreementData =
          ByteBuffer.allocate(data.length + epkSdEckaTlv.getBytes().length)
              .put(data)
              .put(epkSdEckaTlv.getBytes())
              .array();
      byte[] sharedInfo =
          ByteBuffer.allocate(keyUsage.length + keyType.length + keyLen.length)
              .put(keyUsage)
              .put(keyType)
              .put(keyLen)
              .array();

      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");

      keyAgreement.init(ephemeralOceEcka.getPrivate());
      keyAgreement.doPhase(
          PublicKeyValues.Ec.fromEncodedPoint(epkOceEcka.getCurveParams(), epkSdEckaEncodedPoint)
              .toPublicKey(),
          true);
      byte[] ka1 = keyAgreement.generateSecret();

      keyAgreement.init(skOceEcka);
      keyAgreement.doPhase(pk, true);
      byte[] ka2 = keyAgreement.generateSecret();

      byte[] keyMaterial = ByteBuffer.allocate(ka1.length + ka2.length).put(ka1).put(ka2).array();

      List<SecretKey> keys = new ArrayList<>();
      int counter = 1;
      // We need 5 16-byte keys, which requires 3 iterations of SHA256
      for (int i = 0; i < 3; i++) {
        MessageDigest hash = MessageDigest.getInstance("SHA256");
        hash.update(keyMaterial);
        hash.update(ByteBuffer.allocate(4).putInt(counter++).array());
        hash.update(sharedInfo);
        // Each iteration gives us 2 keys
        byte[] digest = hash.digest();
        keys.add(new SecretKeySpec(digest, 0, 16, "AES"));
        keys.add(new SecretKeySpec(digest, 16, 16, "AES"));
        Arrays.fill(digest, (byte) 0);
      }

      // 6 keys were derived. one for verification of receipt, 4 keys to use, and 1 which is
      // discarded
      SecretKey key = keys.get(0);
      Mac mac = Mac.getInstance("AESCMAC");
      mac.init(key);
      byte[] genReceipt = mac.doFinal(keyAgreementData);
      if (!MessageDigest.isEqual(receipt, genReceipt)) {
        throw new BadResponseException("Receipt does not match");
      }
      return new ScpState(
          new SessionKeys(keys.get(1), keys.get(2), keys.get(3), keys.get(4)), receipt);
    } catch (NoSuchAlgorithmException
        | InvalidKeySpecException
        | InvalidAlgorithmParameterException
        | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }

  static byte[] cbcEncrypt(SecretKey key, byte[] data) {
    try {
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
      return cipher.doFinal(data);
    } catch (NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | IllegalBlockSizeException
        | BadPaddingException e) {
      throw new RuntimeException(e);
    }
  }
}

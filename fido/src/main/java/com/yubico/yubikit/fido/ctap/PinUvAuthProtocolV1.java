/*
 * Copyright (C) 2020-2024 Yubico.
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

package com.yubico.yubikit.fido.ctap;

import com.yubico.yubikit.core.util.Pair;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements PIN/UV Auth Protocol 1
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorClientPIN">authenticatorClientPIN</a>.
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto1">PIN/UV
 *     Auth Protocol One</a>.
 */
public class PinUvAuthProtocolV1 implements PinUvAuthProtocol {
  public static final int VERSION = 1;

  private static final String HASH_ALG = "SHA-256";
  private static final String MAC_ALG = "HmacSHA256";
  private static final String CIPHER_ALG = "AES";
  private static final String CIPHER_TRANSFORMATION = "AES/CBC/NoPadding";
  private static final String KEY_AGREEMENT_ALG = "ECDH";
  private static final String KEY_AGREEMENT_KEY_ALG = "EC";

  private static final byte[] IV = new byte[16]; // All zero IV

  private static final int COORDINATE_SIZE = 32;
  private static final int AUTHENTICATE_HASH_LEN = 16;

  private static final int KEY_SHAREDSECRET_POINT_X = -2;
  private static final int KEY_SHAREDSECRET_POINT_Y = -3;

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  public Pair<Map<Integer, ?>, byte[]> encapsulate(Map<Integer, ?> peerCoseKey) {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_AGREEMENT_KEY_ALG);
      kpg.initialize(256); // SECP256R1
      KeyPair kp = kpg.generateKeyPair();
      ECPoint point = ((ECPublicKey) kp.getPublic()).getW();
      Map<Integer, Object> keyAgreement = new HashMap<>();
      keyAgreement.put(1, 2);
      keyAgreement.put(3, -25);
      keyAgreement.put(-1, 1);
      keyAgreement.put(KEY_SHAREDSECRET_POINT_X, encodeCoordinate(point.getAffineX()));
      keyAgreement.put(KEY_SHAREDSECRET_POINT_Y, encodeCoordinate(point.getAffineY()));

      ECPoint w =
          new ECPoint(
              new BigInteger(1, ((byte[]) peerCoseKey.get(KEY_SHAREDSECRET_POINT_X))),
              new BigInteger(1, ((byte[]) peerCoseKey.get(KEY_SHAREDSECRET_POINT_Y))));
      ECPublicKeySpec otherKeySpec =
          new ECPublicKeySpec(w, ((ECPublicKey) kp.getPublic()).getParams());
      KeyFactory keyFactory = KeyFactory.getInstance(KEY_AGREEMENT_KEY_ALG);
      ECPublicKey otherKey = (ECPublicKey) keyFactory.generatePublic(otherKeySpec);

      KeyAgreement ecdh = KeyAgreement.getInstance(KEY_AGREEMENT_ALG);
      ecdh.init(kp.getPrivate());
      ecdh.doPhase(otherKey, true);
      byte[] sharedSecret = kdf(ecdh.generateSecret());
      return new Pair<>(keyAgreement, sharedSecret);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public byte[] kdf(byte[] z) {
    try {
      return MessageDigest.getInstance(HASH_ALG).digest(z);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  @SuppressFBWarnings(
      value = {"CIPHER_INTEGRITY", "STATIC_IV"},
      justification =
          "No padding is performed as the size of demPlaintext is required "
              + "to be a multiple of the AES block length. The specification for "
              + "PIN/UV Auth Protocol One expects all null IV")
  @Override
  public byte[] encrypt(byte[] key, byte[] demPlaintext) {
    try {
      Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, CIPHER_ALG), new IvParameterSpec(IV));
      return cipher.doFinal(demPlaintext);
    } catch (NoSuchAlgorithmException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | NoSuchPaddingException
        | BadPaddingException
        | IllegalBlockSizeException e) {
      throw new IllegalStateException(e);
    }
  }

  @SuppressFBWarnings(
      value = "CIPHER_INTEGRITY",
      justification =
          "No padding is performed as the size of demPlaintext is required "
              + "to be a multiple of the AES block length.")
  @Override
  public byte[] decrypt(byte[] key, byte[] demCiphertext) {
    try {
      Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, CIPHER_ALG), new IvParameterSpec(IV));
      return cipher.doFinal(demCiphertext);
    } catch (NoSuchAlgorithmException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | NoSuchPaddingException
        | BadPaddingException
        | IllegalBlockSizeException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public byte[] authenticate(byte[] key, byte[] message) {
    Mac mac;
    try {
      mac = Mac.getInstance(MAC_ALG);
      mac.init(new SecretKeySpec(key, MAC_ALG));
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
    return Arrays.copyOf(mac.doFinal(message), AUTHENTICATE_HASH_LEN);
  }

  /** Encode a BigInteger as a 32 byte array. */
  static byte[] encodeCoordinate(BigInteger value) {
    byte[] valueBytes = value.toByteArray();
    byte[] result = new byte[COORDINATE_SIZE];
    if (valueBytes.length < COORDINATE_SIZE) { // Left pad with zeroes
      System.arraycopy(valueBytes, 0, result, result.length - valueBytes.length, valueBytes.length);
    } else if (valueBytes.length > COORDINATE_SIZE) { // Truncate from left
      System.arraycopy(valueBytes, valueBytes.length - COORDINATE_SIZE, result, 0, COORDINATE_SIZE);
    } else {
      result = valueBytes;
    }
    return result;
  }
}

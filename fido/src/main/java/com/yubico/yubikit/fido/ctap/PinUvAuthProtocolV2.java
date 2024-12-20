/*
 * Copyright (C) 2023-2024 Yubico.
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

import com.yubico.yubikit.core.util.RandomUtils;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements PIN/UV Auth Protocol 2
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorClientPIN">authenticatorClientPIN</a>.
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto2">PIN/UV
 *     Auth Protocol Two</a>.
 */
public class PinUvAuthProtocolV2 extends PinUvAuthProtocolV1 {
  public static final int VERSION = 2;

  private static final String HKDF_ALG = "HmacSHA256";
  private static final byte[] HKDF_SALT = new byte[32];
  private static final byte[] HKDF_INFO_HMAC = "CTAP2 HMAC key".getBytes(StandardCharsets.UTF_8);
  private static final byte[] HKDF_INFO_AES = "CTAP2 AES key".getBytes(StandardCharsets.UTF_8);
  private static final int HKDF_LENGTH = 32;

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  public byte[] kdf(byte[] z) {
    byte[] hmacKey = null;
    byte[] aesKey = null;
    try {
      hmacKey = new Hkdf(HKDF_ALG).digest(z, HKDF_SALT, HKDF_INFO_HMAC, HKDF_LENGTH);

      aesKey = new Hkdf(HKDF_ALG).digest(z, HKDF_SALT, HKDF_INFO_AES, HKDF_LENGTH);

      return ByteBuffer.allocate(hmacKey.length + aesKey.length).put(hmacKey).put(aesKey).array();
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new IllegalStateException(e);
    } finally {
      if (hmacKey != null) {
        Arrays.fill(hmacKey, (byte) 0);
      }
      if (aesKey != null) {
        Arrays.fill(aesKey, (byte) 0);
      }
    }
  }

  @Override
  public byte[] encrypt(byte[] key, byte[] plaintext) {
    byte[] aesKey = null;
    try {
      aesKey = Arrays.copyOfRange(key, 32, key.length);
      byte[] iv = RandomUtils.getRandomBytes(16);

      final byte[] ciphertext = getCipher(Cipher.ENCRYPT_MODE, aesKey, iv).doFinal(plaintext);
      return ByteBuffer.allocate(iv.length + ciphertext.length).put(iv).put(ciphertext).array();
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new IllegalStateException(e);
    } finally {
      if (aesKey != null) {
        Arrays.fill(aesKey, (byte) 0);
      }
    }
  }

  @Override
  public byte[] decrypt(byte[] key, byte[] ciphertext) {
    byte[] aesKey = null;
    try {
      aesKey = Arrays.copyOfRange(key, 32, key.length);
      byte[] iv = Arrays.copyOf(ciphertext, 16);
      byte[] ct = Arrays.copyOfRange(ciphertext, 16, ciphertext.length);
      return getCipher(Cipher.DECRYPT_MODE, aesKey, iv).doFinal(ct);
    } catch (BadPaddingException | IllegalBlockSizeException e) {
      throw new IllegalStateException(e);
    } finally {
      if (aesKey != null) {
        Arrays.fill(aesKey, (byte) 0);
      }
    }
  }

  @Override
  public byte[] authenticate(byte[] key, byte[] message) {
    final String MAC_ALG = "HmacSHA256";
    byte[] hmacKey = Arrays.copyOf(key, 32);
    Mac mac;
    try {
      mac = Mac.getInstance(MAC_ALG);
      mac.init(new SecretKeySpec(hmacKey, MAC_ALG));
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
    return mac.doFinal(message);
  }

  @SuppressFBWarnings(
      value = {"CIPHER_INTEGRITY", "STATIC_IV"},
      justification =
          "No padding is performed as the size of demPlaintext is required "
              + "to be a multiple of the AES block length. The IV is randomly generated "
              + "for every encrypt operation")
  private Cipher getCipher(int mode, byte[] secret, byte[] iv) {
    try {
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(mode, new SecretKeySpec(secret, "AES"), new IvParameterSpec(iv));
      return cipher;
    } catch (NoSuchPaddingException
        | NoSuchAlgorithmException
        | InvalidAlgorithmParameterException
        | InvalidKeyException e) {
      throw new IllegalStateException(e);
    }
  }
}

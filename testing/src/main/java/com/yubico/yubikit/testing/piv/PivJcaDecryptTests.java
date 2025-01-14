/*
 * Copyright (C) 2022-2024 Yubico.
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

package com.yubico.yubikit.testing.piv;

import static com.yubico.yubikit.piv.PivSession.FEATURE_RSA3072_RSA4096;
import static com.yubico.yubikit.testing.piv.PivJcaUtils.setupJca;
import static com.yubico.yubikit.testing.piv.PivJcaUtils.tearDownJca;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;
import com.yubico.yubikit.piv.jca.PivAlgorithmParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PivJcaDecryptTests {

  private static final Logger logger = LoggerFactory.getLogger(PivJcaDecryptTests.class);

  public static void testDecrypt(PivSession piv, PivTestState state)
      throws BadResponseException,
          IOException,
          ApduException,
          NoSuchPaddingException,
          NoSuchAlgorithmException,
          InvalidKeyException,
          BadPaddingException,
          IllegalBlockSizeException,
          InvalidAlgorithmParameterException {
    setupJca(piv);
    for (KeyType keyType : KeyType.values()) {
      if (((keyType == KeyType.RSA3072 || keyType == KeyType.RSA4096)
          && !piv.supports(FEATURE_RSA3072_RSA4096))) {
        continue; // Run only on compatible keys
      }
      if (keyType.params.algorithm.name().equals("RSA")) {
        testDecrypt(piv, state, keyType);
      }
    }
    tearDownJca();
  }

  public static void testDecrypt(PivSession piv, PivTestState state, KeyType keyType)
      throws BadResponseException,
          IOException,
          ApduException,
          NoSuchPaddingException,
          NoSuchAlgorithmException,
          InvalidKeyException,
          BadPaddingException,
          IllegalBlockSizeException,
          InvalidAlgorithmParameterException {

    if (keyType.params.algorithm != KeyType.Algorithm.RSA) {
      throw new IllegalArgumentException("Unsupported");
    }

    if (state.isInvalidKeyType(keyType)) {
      return;
    }

    piv.authenticate(state.managementKey);
    logger.debug("Generate key: {}", keyType);
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("YKPivRSA");
    kpg.initialize(
        new PivAlgorithmParameterSpec(
            Slot.KEY_MANAGEMENT, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT, state.pin));
    KeyPair pair = kpg.generateKeyPair();

    testDecrypt(pair, Cipher.getInstance("RSA/ECB/PKCS1Padding"));
    testDecrypt(pair, Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"));
    testDecrypt(pair, Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));
  }

  public static void testDecrypt(KeyPair keyPair, Cipher cipher)
      throws NoSuchPaddingException,
          NoSuchAlgorithmException,
          InvalidKeyException,
          BadPaddingException,
          IllegalBlockSizeException {
    byte[] message = "Hello world!".getBytes(StandardCharsets.UTF_8);

    logger.debug("Using cipher {}", cipher.getAlgorithm());

    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    byte[] ct = cipher.doFinal(message);
    logger.debug("Cipher text {}: {}", ct.length, StringUtils.bytesToHex(ct));

    Cipher decryptCipher = Cipher.getInstance(cipher.getAlgorithm());
    decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    byte[] pt = decryptCipher.doFinal(ct);

    Assert.assertArrayEquals(message, pt);
    logger.debug("Decrypt successful for {}", cipher.getAlgorithm());
  }
}

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

package com.yubico.yubikit.testing.piv;

import static com.yubico.yubikit.piv.PivSession.FEATURE_RSA3072_RSA4096;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PivCertificateTests {
  private static final Logger logger = LoggerFactory.getLogger(PivCertificateTests.class);

  public static void putUncompressedCertificate(PivSession piv, PivTestState state)
      throws IOException, ApduException, CertificateException, BadResponseException {
    putCertificate(piv, state, false);
  }

  public static void putCompressedCertificate(PivSession piv, PivTestState state)
      throws IOException, ApduException, CertificateException, BadResponseException {
    putCertificate(piv, state, true);
  }

  private static void putCertificate(PivSession piv, PivTestState state, boolean compressed)
      throws IOException, ApduException, CertificateException, BadResponseException {
    piv.authenticate(state.managementKey);

    for (KeyType keyType :
        Arrays.asList(
            KeyType.ECCP256,
            KeyType.ECCP384,
            KeyType.RSA1024,
            KeyType.RSA2048,
            KeyType.RSA3072,
            KeyType.RSA4096)) {

      if (((keyType == KeyType.RSA3072 || keyType == KeyType.RSA4096)
          && !piv.supports(FEATURE_RSA3072_RSA4096))) {
        continue; // Run only on compatible keys
      }

      Slot slot = Slot.SIGNATURE;
      logger.info(
          "Putting {} {} certificate to slot {}",
          compressed ? "compressed" : "not compressed",
          keyType.name(),
          slot.name());
      KeyPair keyPair = PivTestUtils.loadKey(keyType);
      X509Certificate cert = PivTestUtils.createCertificate(keyPair);
      piv.putCertificate(slot, cert, compressed);

      // get and compare cert
      logger.debug("Getting {} certificate from slot {}", keyType.name(), slot.name());
      X509Certificate loadedCert = piv.getCertificate(slot);
      Assert.assertEquals(cert, loadedCert);
    }
  }
}

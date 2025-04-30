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
package com.yubico.yubikit.testing.piv;

import static com.yubico.yubikit.testing.piv.PivJcaUtils.setupJca;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNoException;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.application.InvalidPinException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.BioMetadata;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;
import com.yubico.yubikit.piv.jca.PivAlgorithmParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import org.junit.Assert;

public class PivBioMultiProtocolDeviceTests {

  /**
   * Verify authentication with YubiKey Bio Multi-protocol.
   *
   * <p>To run the test, create a PIN and enroll at least one fingerprint. The test will ask twice
   * for fingerprint authentication.
   */
  public static void testAuthenticate(PivSession piv, PivTestState ignored)
      throws IOException, ApduException, InvalidPinException {
    try {
      BioMetadata bioMetadata = piv.getBioMetadata();

      // we have correct key, is it configured?
      assumeTrue("Key has no bio multi-protocol functionality", bioMetadata.isConfigured());
      assumeTrue("Key has no matches left", bioMetadata.getAttemptsRemaining() > 0);

      assertNull(piv.verifyUv(false, false));
      assertFalse(piv.getBioMetadata().hasTemporaryPin());

      // check verified state
      assertNull(piv.verifyUv(false, true));

      byte[] pin = piv.verifyUv(true, false);
      assertNotNull(pin);
      assertTrue(piv.getBioMetadata().hasTemporaryPin());

      // check verified state
      assertNull(piv.verifyUv(false, true));

      piv.verifyTemporaryPin(pin);

    } catch (UnsupportedOperationException e) {
      assumeNoException("Key has no bio multi-protocol functionality", e);
    }
  }

  /**
   * Verify signing with YubiKey Bio Multi-protocol with PIN and with Fingerprint match
   *
   * <p>To run the test, create a PIN "11234567" and enroll at least one fingerprint. The test will
   *
   * <ul>
   *   <li>use PIN to sign a message
   *   <li>use Fingerprint match to sign a message (this will ask for fingerprint)
   * </ul>
   */
  public static void testSign(PivSession piv, PivTestState state) throws Exception {
    try {

      setupJca(piv);
      piv.authenticate(state.managementKey);

      BioMetadata bioMetadata = piv.getBioMetadata();

      // we have correct key, is it configured?
      assumeTrue("Key has no bio multi-protocol functionality", bioMetadata.isConfigured());
      assumeTrue("Key has no matches left", bioMetadata.getAttemptsRemaining() > 0);

      // 1. sign with PIN verification
      {
        // generate a new key pair in the signature slot
        final KeyType keyType = KeyType.ED25519;
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("YKPiv" + keyType.params.algorithm.name());
        kpg.initialize(
            // see that pin is not null - the private key will call pivSession.verifyPin()
            new PivAlgorithmParameterSpec(
                Slot.SIGNATURE, keyType, PinPolicy.MATCH_ALWAYS, TouchPolicy.DEFAULT, state.pin));
        KeyPair keyPair = kpg.generateKeyPair();

        // message to sign
        byte[] message = "Hello there".getBytes(StandardCharsets.UTF_8);

        // use JCA for the signature
        Signature signer = Signature.getInstance(KeyType.ED25519.name());
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();

        // verify the signature with JCA
        Signature verifier = Signature.getInstance(KeyType.ED25519.name());
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        Assert.assertTrue("Verify signature", verifier.verify(signature));
      }

      // 2. sign with Fingerprint match verification
      {
        // we obtain the temporary pin
        byte[] temporaryPin = piv.verifyUv(true, false);
        assertNotNull(temporaryPin);
        assertTrue(piv.getBioMetadata().hasTemporaryPin());

        // generate a new key pair in the signature slot
        final KeyType keyType = KeyType.ED25519;
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("YKPiv" + keyType.params.algorithm.name());
        kpg.initialize(
            // see that pin is null - the private key will not call pivSession.verifyPin()
            new PivAlgorithmParameterSpec(
                Slot.SIGNATURE, keyType, PinPolicy.MATCH_ALWAYS, TouchPolicy.DEFAULT, null));
        KeyPair keyPair = kpg.generateKeyPair();

        // use temporary pin obtained from UV
        // this is needed the private key operation
        // replaces pivSession.verifyPin()
        piv.verifyTemporaryPin(temporaryPin);

        // message to sign
        byte[] message = "Hello there".getBytes(StandardCharsets.UTF_8);

        // sign data with the key pair in the signature slot
        // this will not work for RSA or EC unless the message is properly formatted but works for
        // ED25519
        byte[] signature = piv.rawSignOrDecrypt(Slot.SIGNATURE, keyType, message);

        // verify the signature with JCA
        Signature verifier = Signature.getInstance(KeyType.ED25519.name());
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        Assert.assertTrue("Verify signature", verifier.verify(signature));
      }

    } catch (Exception e) {
      assumeNoException("Exception: ", e);
    }
  }
}

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
import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.piv.BioMetadata;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.SlotMetadata;
import com.yubico.yubikit.piv.jca.PivPrivateKey;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import javax.annotation.Nullable;
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
   * <p>To run the test setup the YubiKey Bio Multi-protocol Edition in following way:
   *
   * <ul>
   *   <li>change PIN to "11234567"
   *   <li>keep default Management Key
   *   <li>enroll fingerprint(s)
   *   <li>generate/import EC, RSA or ED25519 key into SIGNATURE slot
   *   <li>make sure correct certificate is also present
   * </ul>
   *
   * The test will get the keypair from the SIGNATURE slot and:
   *
   * <ul>
   *   <li>use PIN to sign a message
   *   <li>use a Fingerprint match to sign a message (this will make the YubiKey blink)
   * </ul>
   */
  public static void testSign(PivSession piv, PivTestState state) throws Exception {
    try {

      Slot slot = Slot.SIGNATURE;

      setupJca(piv);
      piv.authenticate(state.managementKey);

      BioMetadata bioMetadata = piv.getBioMetadata();

      // we have correct key, is it configured?
      assumeTrue("Key has no bio multi-protocol functionality", bioMetadata.isConfigured());
      assumeTrue("Key has no matches left", bioMetadata.getAttemptsRemaining() > 0);

      // use PIN to sign a message
      testBioMpeSign(piv, slot, state.pin, null);

      byte[] temporaryPin = piv.verifyUv(true, false);
      assertNotNull(temporaryPin);
      assertTrue(piv.getBioMetadata().hasTemporaryPin());

      // use temporary pin to sign a message
      testBioMpeSign(piv, slot, null, temporaryPin);

    } catch (Exception e) {
      assumeNoException("Exception: ", e);
    }
  }

  private static void testBioMpeSign(
      PivSession piv, Slot slot, @Nullable char[] pin, @Nullable byte[] temporaryPin)
      throws Exception {

    if (pin != null && temporaryPin != null) {
      throw new IllegalArgumentException("Both pin and temporaryPin cannot be set");
    }

    if (pin == null && temporaryPin == null) {
      throw new IllegalArgumentException("Either pin or temporaryPin must be set");
    }

    // get key pair
    KeyStore keyStore = KeyStore.getInstance("YKPiv");
    keyStore.load(null);
    // if the pin parameter is not null, PivPrivateKey will internally call verifyPin with it
    PrivateKey privateKey = (PivPrivateKey) keyStore.getKey(slot.getStringAlias(), pin);
    Certificate certificate = keyStore.getCertificate(slot.getStringAlias());

    SlotMetadata slotMetadata = piv.getSlotMetadata(slot);

    // decide hash algorithm based on key type
    KeyType slotKeyType = slotMetadata.getKeyType();
    String signatureAlgorithm;
    // use signature algorithm based on your needs,
    // this is just an example
    switch (slotKeyType) {
      case ED25519:
        signatureAlgorithm = "ED25519";
        break;
      case ECCP256:
      case ECCP384:
        signatureAlgorithm = "SHA3-256withECDSA";
        break;
      case RSA1024:
      case RSA2048:
      case RSA3072:
      case RSA4096:
        signatureAlgorithm = "SHA256withRSA";
        break;
      case X25519:
      default:
        throw new IllegalStateException("Key type not supported");
    }

    // verify
    if (temporaryPin != null) {
      piv.verifyTemporaryPin(temporaryPin);
    }

    // message to sign
    byte[] message =
        slotKeyType == KeyType.ED25519
            ? RandomUtils.getRandomBytes(2048) // ED25519 is limited by APDU size
            : RandomUtils.getRandomBytes(1024 * 1024);

    // sign
    Signature signer = Signature.getInstance(signatureAlgorithm);
    signer.initSign(privateKey);
    signer.update(message);
    byte[] signature = signer.sign();

    // verify
    Signature verifier = Signature.getInstance(signatureAlgorithm);
    verifier.initVerify(certificate.getPublicKey());
    verifier.update(message);
    Assert.assertTrue("Verify signature", verifier.verify(signature));
  }
}

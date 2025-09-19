/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.testing.fido;

import static com.yubico.yubikit.testing.fido.utils.BioEnrollment.enrollFingerprint;
import static com.yubico.yubikit.testing.fido.utils.BioEnrollment.fpBioEnrollment;
import static com.yubico.yubikit.testing.fido.utils.BioEnrollment.removeAllFingerprints;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.BioEnrollment;
import com.yubico.yubikit.fido.ctap.FingerprintBioEnrollment;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.UserVerificationRequirement;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Ctap2BioUvTests {

  private static final Logger logger = LoggerFactory.getLogger(Ctap2BioUvTests.class);

  /**
   * Needs to be ran manually with a Bio device.
   *
   * <p>Verifies that after blocking Bio UV by three failed matches, PIN can be used to perform UV.
   * See logger.info output for instructions:
   *
   * <p>The test does following:
   *
   * <ol>
   *   <li>resets the device, sets default PIN
   *   <li>asks for fingerprint enrollments -> touch the fp sensor 5x with finger 1
   *   <li>calls make credential 3x -> touch the fp sensor 3x with finger 2 (UV_INVALID)
   *   <li>calls make credential with PIN -> touch the sensor
   *   <li>removes new credential and created fingerprint
   * </ol>
   *
   * @param state test state
   * @throws Throwable on any test error
   */
  public static void testPinRequiredAfterUvBlocked(FidoTestState state) throws Throwable {

    final byte[] templateId =
        state.withCtap2(
            session -> {
              assumeTrue(
                  "Bio enrollment not supported",
                  BioEnrollment.isSupported(session.getCachedInfo()));

              final FingerprintBioEnrollment fingerprintBioEnrollment =
                  fpBioEnrollment(session, state);

              removeAllFingerprints(fingerprintBioEnrollment);

              return enrollFingerprint(fingerprintBioEnrollment);
            });

    // MC with fingerprint
    for (int i = 0; i < 4; i++) {
      final int innerI = i;
      state.withCtap2(
          session -> {
            try {
              logger.info("Use wrong fingerprint");
              new ClientHelper(session)
                  .withPin(null)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .userEntity("Bio User")
                          .residentKey(true)
                          .userVerification(UserVerificationRequirement.REQUIRED)
                          .build());

            } catch (ClientError e) {
              if (e.getErrorCode() == ClientError.Code.BAD_REQUEST) {
                if (e.getCause() instanceof CtapException) {
                  CtapException ctapException = (CtapException) e.getCause();
                  if (innerI < 3) {
                    // first three wrong matches
                    assertEquals(CtapException.ERR_UV_INVALID, ctapException.getCtapError());
                    logger.info("Received UV Invalid");
                  } else {
                    // three wrong matches block UV
                    assertEquals(CtapException.ERR_UV_BLOCKED, ctapException.getCtapError());
                    logger.info("Received UV Blocked");
                  }
                }
              }
            }
          });
    }

    PublicKeyCredential cred =
        state.withCtap2(
            session -> {
              logger.info("Touch the sensor (no fingerprint scan)");

              return new ClientHelper(session)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .userEntity("Bio User")
                          .residentKey(true)
                          // even when UV is required, PIN will be used
                          .userVerification(UserVerificationRequirement.REQUIRED)
                          .build());
            });

    state.withCtap2(
        session -> {
          final FingerprintBioEnrollment fingerprintBioEnrollment = fpBioEnrollment(session, state);
          fingerprintBioEnrollment.removeEnrollment(templateId);
          new ClientHelper(session).deleteCredentials(cred);
        });
  }
}

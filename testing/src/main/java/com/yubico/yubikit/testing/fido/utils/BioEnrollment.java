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

package com.yubico.yubikit.testing.fido.utils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.FingerprintBioEnrollment;
import com.yubico.yubikit.testing.fido.FidoTestState;
import java.util.Arrays;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BioEnrollment {
  private static final Logger logger = LoggerFactory.getLogger(BioEnrollment.class);

  public static byte[] enrollFingerprint(FingerprintBioEnrollment bioEnrollment) {

    final FingerprintBioEnrollment.Context context = bioEnrollment.enroll(null);

    byte[] templateId = null;
    while (templateId == null) {
      logger.info("Touch the fingerprint");
      try {
        templateId = context.capture(null);
      } catch (FingerprintBioEnrollment.CaptureError captureError) {
        // capture errors are expected
        logger.info("Received capture error: ", captureError);
      } catch (CtapException ctapException) {
        assertThat(
            "Received CTAP2_ERR_FP_DATABASE_FULL exception - "
                + "remove fingerprints before running this test",
            ctapException.getCtapError() != CtapException.ERR_FP_DATABASE_FULL);
        fail("Received unexpected CTAP2 exception " + ctapException.getCtapError());
      } catch (Throwable exception) {
        fail("Received unexpected exception " + exception.getMessage());
      }
    }

    logger.info("Enrolled: {}", templateId);

    return templateId;
  }

  public static FingerprintBioEnrollment fpBioEnrollment(Ctap2Session session, FidoTestState state)
      throws Throwable {

    final ClientPin pin = new ClientPin(session, state.getPinUvAuthProtocol());
    final byte[] pinToken = pin.getPinToken(TestData.PIN, ClientPin.PIN_PERMISSION_BE, "localhost");

    return new FingerprintBioEnrollment(session, state.getPinUvAuthProtocol(), pinToken);
  }

  public static void renameFingerprint(
      FingerprintBioEnrollment fingerprintBioEnrollment, byte[] templateId, int newNameLen)
      throws Throwable {

    char[] charArray = new char[newNameLen];
    Arrays.fill(charArray, 'A');
    String newName = new String(charArray);

    fingerprintBioEnrollment.setName(templateId, newName);
    Map<byte[], String> enrollments = fingerprintBioEnrollment.enumerateEnrollments();
    assertEquals(newName, getName(templateId, enrollments));
  }

  public static void removeAllFingerprints(FingerprintBioEnrollment fingerprintBioEnrollment)
      throws Throwable {
    Map<byte[], String> enrollments = fingerprintBioEnrollment.enumerateEnrollments();

    for (byte[] templateId : enrollments.keySet()) {
      fingerprintBioEnrollment.removeEnrollment(templateId);
    }

    enrollments = fingerprintBioEnrollment.enumerateEnrollments();
    assertThat("Fingerprints still exists after removal", enrollments.isEmpty());
  }

  public static boolean isEnrolled(byte[] templateId, Map<byte[], String> enrollments) {
    for (byte[] enrolledTemplateId : enrollments.keySet()) {
      if (Arrays.equals(templateId, enrolledTemplateId)) {
        return true;
      }
    }
    return false;
  }

  public static String getName(byte[] templateId, Map<byte[], String> enrollments) {
    for (Map.Entry<byte[], String> enrollment : enrollments.entrySet()) {
      if (Arrays.equals(templateId, enrollment.getKey())) {
        return enrollments.get(enrollment.getKey());
      }
    }
    return null;
  }
}

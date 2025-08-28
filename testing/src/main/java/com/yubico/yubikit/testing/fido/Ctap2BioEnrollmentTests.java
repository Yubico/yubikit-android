/*
 * Copyright (C) 2024-2025 Yubico.
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
import static com.yubico.yubikit.testing.fido.utils.BioEnrollment.isEnrolled;
import static com.yubico.yubikit.testing.fido.utils.BioEnrollment.removeAllFingerprints;
import static com.yubico.yubikit.testing.fido.utils.BioEnrollment.renameFingerprint;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.fido.ctap.BioEnrollment;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.FingerprintBioEnrollment;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Ctap2BioEnrollmentTests {

  private static final Logger logger = LoggerFactory.getLogger(Ctap2BioEnrollmentTests.class);

  public static void testFingerprintEnrollment(Ctap2Session session, FidoTestState state)
      throws Throwable {

    assumeTrue("Bio enrollment not supported", BioEnrollment.isSupported(session.getCachedInfo()));

    final FingerprintBioEnrollment fingerprintBioEnrollment = fpBioEnrollment(session, state);

    removeAllFingerprints(fingerprintBioEnrollment);

    final byte[] templateId = enrollFingerprint(fingerprintBioEnrollment);

    Map<byte[], String> enrollments = fingerprintBioEnrollment.enumerateEnrollments();
    assertTrue(isEnrolled(templateId, enrollments));

    final int maxNameLen = fingerprintBioEnrollment.getSensorInfo().getMaxTemplateFriendlyName();

    renameFingerprint(fingerprintBioEnrollment, templateId, maxNameLen);
    try {
      renameFingerprint(fingerprintBioEnrollment, templateId, maxNameLen + 1);
      fail("Expected exception after rename with long name");
    } catch (CtapException e) {
      assertEquals(CtapException.ERR_INVALID_LENGTH, e.getCtapError());
      logger.debug("Caught ERR_INVALID_LENGTH when using long name.");
    }

    fingerprintBioEnrollment.removeEnrollment(templateId);
    enrollments = fingerprintBioEnrollment.enumerateEnrollments();
    assertThat("Fingerprints still exists after removal", enrollments.isEmpty());
  }
}

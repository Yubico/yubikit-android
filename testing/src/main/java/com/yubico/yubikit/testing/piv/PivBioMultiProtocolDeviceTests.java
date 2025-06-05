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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNoException;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.application.InvalidPinException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.BioMetadata;
import com.yubico.yubikit.piv.PivSession;
import java.io.IOException;

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
}

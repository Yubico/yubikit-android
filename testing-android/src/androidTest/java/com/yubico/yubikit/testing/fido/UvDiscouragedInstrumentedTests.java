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

package com.yubico.yubikit.testing.fido;

import com.yubico.yubikit.fido.client.PinRequiredClientError;
import com.yubico.yubikit.testing.AlwaysManualTest;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class UvDiscouragedInstrumentedTests extends FidoInstrumentedTests {
  /**
   * Reset the FIDO application before running this test.
   *
   * <p>The test will make credential/get assertion without using the PIN which is acceptable for
   * {@code UserVerificationRequirement.DISCOURAGED}.
   *
   * <p>Skipped on FIPS approved devices.
   */
  @Test
  @Category(AlwaysManualTest.class)
  public void testMakeCredentialGetAssertion() throws Throwable {
    withDevice(false, BasicWebAuthnClientTests::testUvDiscouragedMcGa_noPin);
  }

  /**
   * This test will make credential without passing PIN value on a device which is protected by PIN.
   *
   * <p>Expected to fail with PinRequiredClientError
   */
  @Test(expected = PinRequiredClientError.class)
  public void testMakeCredentialGetAssertionWithPin() throws Throwable {
    withDevice(BasicWebAuthnClientTests::testUvDiscouragedMcGa_withPin);
  }
}

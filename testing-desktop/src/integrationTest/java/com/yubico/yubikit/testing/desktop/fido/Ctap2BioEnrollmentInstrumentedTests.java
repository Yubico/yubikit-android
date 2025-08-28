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
package com.yubico.yubikit.testing.desktop.fido;

import com.yubico.yubikit.testing.desktop.AlwaysManualTest;
import com.yubico.yubikit.testing.desktop.framework.FidoInstrumentedTests;
import com.yubico.yubikit.testing.fido.Ctap2BioEnrollmentTests;
import com.yubico.yubikit.testing.fido.Ctap2BioUvTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class Ctap2BioEnrollmentInstrumentedTests extends FidoInstrumentedTests {
  @Test
  public void testFingerprintEnrollment() throws Throwable {
    withCtap2Session(Ctap2BioEnrollmentTests::testFingerprintEnrollment);
  }

  @Test
  @Category(AlwaysManualTest.class)
  public void testPinRequiredAfterUvBlocked() throws Throwable {
    withDevice(Ctap2BioUvTests::testPinRequiredAfterUvBlocked);
  }
}

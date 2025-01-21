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

import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.testing.desktop.AlwaysManualTest;
import com.yubico.yubikit.testing.desktop.PinUvAuthProtocolV1Test;
import com.yubico.yubikit.testing.desktop.framework.FidoInstrumentedTests;
import com.yubico.yubikit.testing.fido.Ctap2SessionTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * Tests FIDO Reset.
 *
 * <p>This is a manual test which will reset the FIDO application.
 *
 * <ul>
 *   <li>Before running the test, disconnect the YubiKey from the Android device.
 *   <li>YubiKey Bio devices are currently ignored.
 * </ul>
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
  Ctap2SessionResetInstrumentedTests.PinUvAuthV2Test.class,
  Ctap2SessionResetInstrumentedTests.PinUvAuthV1Test.class,
})
public class Ctap2SessionResetInstrumentedTests {
  public static class PinUvAuthV2Test extends FidoInstrumentedTests {
    @Test
    @Category(AlwaysManualTest.class)
    public void testReset() throws Throwable {
      withDevice(false, Ctap2SessionTests::testReset);
    }
  }

  @Category(PinUvAuthProtocolV1Test.class)
  public static class PinUvAuthV1Test extends PinUvAuthV2Test {
    @Override
    protected PinUvAuthProtocol getPinUvAuthProtocol() {
      return new PinUvAuthProtocolV1();
    }
  }
}

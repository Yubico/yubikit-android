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
import com.yubico.yubikit.testing.desktop.PinUvAuthProtocolV1Test;
import com.yubico.yubikit.testing.desktop.framework.FidoInstrumentedTests;
import com.yubico.yubikit.testing.fido.Ctap2ClientPinTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  Ctap2ClientPinInstrumentedTests.PinUvAuthV2Test.class,
  Ctap2ClientPinInstrumentedTests.PinUvAuthV1Test.class,
})
public class Ctap2ClientPinInstrumentedTests {
  public static class PinUvAuthV2Test extends FidoInstrumentedTests {
    @Test
    public void testClientPin() throws Throwable {
      withCtap2Session(Ctap2ClientPinTests::testClientPin);
    }

    @Test
    public void testPinComplexity() throws Throwable {
      withDevice(Ctap2ClientPinTests::testPinComplexity);
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

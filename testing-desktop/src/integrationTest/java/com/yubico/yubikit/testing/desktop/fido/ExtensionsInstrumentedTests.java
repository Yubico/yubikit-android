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

package com.yubico.yubikit.testing.desktop.fido;

import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.testing.desktop.PinUvAuthProtocolV1Test;
import com.yubico.yubikit.testing.desktop.framework.FidoInstrumentedTests;
import com.yubico.yubikit.testing.fido.extensions.CredBlobExtensionTests;
import com.yubico.yubikit.testing.fido.extensions.CredPropsExtensionTests;
import com.yubico.yubikit.testing.fido.extensions.CredProtectExtensionTests;
import com.yubico.yubikit.testing.fido.extensions.HmacSecretExtensionTests;
import com.yubico.yubikit.testing.fido.extensions.LargeBlobExtensionTests;
import com.yubico.yubikit.testing.fido.extensions.MinPinLengthExtensionTests;
import com.yubico.yubikit.testing.fido.extensions.PrfExtensionTests;
import com.yubico.yubikit.testing.fido.extensions.ThirdPartyPaymentExtensionTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  ExtensionsInstrumentedTests.PinUvAuthV2Test.class,
  ExtensionsInstrumentedTests.PinUvAuthV1Test.class,
})
public class ExtensionsInstrumentedTests {
  public static class PinUvAuthV2Test extends FidoInstrumentedTests {
    @Test
    public void testCredPropsExtension() throws Throwable {
      withDevice(CredPropsExtensionTests::test);
    }

    @Test
    public void testPrfExtension() throws Throwable {
      withDevice(PrfExtensionTests::testPrf);
    }

    @Test
    public void testPrfHmacSecretMcExtension() throws Throwable {
      withDevice(PrfExtensionTests::testPrfHmacSecretMc);
    }

    @Test
    public void testPrfExtensionNoSupport() throws Throwable {
      withDevice(PrfExtensionTests::testNoExtensionSupport);
    }

    @Test
    public void testHmacSecretExtension() throws Throwable {
      withDevice(HmacSecretExtensionTests::testHmacSecret);
    }

    @Test
    public void testHmacSecretMcExtension() throws Throwable {
      withDevice(HmacSecretExtensionTests::testHmacSecretMc);
    }

    @Test
    public void testHmacSecretExtensionNoSupport() throws Throwable {
      withDevice(HmacSecretExtensionTests::testNoExtensionSupport);
    }

    @Test
    public void testLargeBlobExtension() throws Throwable {
      withDevice(LargeBlobExtensionTests::test);
    }

    @Test
    public void testCredBlobExtension() throws Throwable {
      withDevice(CredBlobExtensionTests::test);
    }

    @Test
    public void testCredProtectExtension() throws Throwable {
      withDevice(CredProtectExtensionTests::test);
    }

    @Test
    public void testMinPinLengthExtension() throws Throwable {
      withDevice(MinPinLengthExtensionTests::test);
    }

    @Test
    public void testThirdPartyPaymentExtension() throws Throwable {
      withDevice(ThirdPartyPaymentExtensionTests::test);
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

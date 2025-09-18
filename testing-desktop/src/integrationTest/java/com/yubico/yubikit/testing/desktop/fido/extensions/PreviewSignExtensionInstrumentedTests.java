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

package com.yubico.yubikit.testing.desktop.fido.extensions;

import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.testing.desktop.PinUvAuthProtocolV1Test;
import com.yubico.yubikit.testing.desktop.framework.FidoInstrumentedTests;
import com.yubico.yubikit.testing.fido.extensions.PreviewSignExtensionTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  PreviewSignExtensionInstrumentedTests.PinUvAuthV2Test.class,
  PreviewSignExtensionInstrumentedTests.PinUvAuthV1Test.class,
})
public class PreviewSignExtensionInstrumentedTests {
  public static class PinUvAuthV2Test extends FidoInstrumentedTests {
    @Test
    public void testWithDiscoverableCredential() throws Throwable {
      withDevice(PreviewSignExtensionTests::testWithDiscoverableCredential);
    }

    @Test
    public void testWithNonDiscoverableCredential() throws Throwable {
      withDevice(PreviewSignExtensionTests::testWithNonDiscoverableCredential);
    }

    @Test
    public void testNoSupport() throws Throwable {
      withDevice(PreviewSignExtensionTests::testNoExtensionSupport);
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

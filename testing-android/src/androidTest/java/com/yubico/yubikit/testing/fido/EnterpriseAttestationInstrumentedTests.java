/*
 * Copyright (C) 2023-2024 Yubico.
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

import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.testing.PinUvAuthProtocolV1Test;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  EnterpriseAttestationInstrumentedTests.PinUvAuthV2Test.class,
  EnterpriseAttestationInstrumentedTests.PinUvAuthV1Test.class,
})
public class EnterpriseAttestationInstrumentedTests {
  public static class PinUvAuthV2Test extends FidoInstrumentedTests {
    @Test
    public void testSupportedPlatformManagedEA() throws Throwable {
      withCtap2Session(EnterpriseAttestationTests::testSupportedPlatformManagedEA);
    }

    @Test
    public void testUnsupportedPlatformManagedEA() throws Throwable {
      withCtap2Session(EnterpriseAttestationTests::testUnsupportedPlatformManagedEA);
    }

    @Test
    public void testCreateOptionsAttestationPreference() throws Throwable {
      withDevice(EnterpriseAttestationTests::testCreateOptionsAttestationPreference);
    }

    @Test
    public void testVendorFacilitatedEA() throws Throwable {
      withCtap2Session(EnterpriseAttestationTests::testVendorFacilitatedEA);
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

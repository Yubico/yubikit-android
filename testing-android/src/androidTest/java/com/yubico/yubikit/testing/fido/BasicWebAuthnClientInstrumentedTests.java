/*
 * Copyright (C) 2022-2025 Yubico.
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
import com.yubico.yubikit.testing.SmokeTest;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  BasicWebAuthnClientInstrumentedTests.PinUvAuthV2Test.class,
  BasicWebAuthnClientInstrumentedTests.PinUvAuthV1Test.class,
})
public class BasicWebAuthnClientInstrumentedTests {
  public static class PinUvAuthV2Test extends FidoInstrumentedTests {

    @Test
    @Category(SmokeTest.class)
    public void testMakeCredentialGetAssertion() throws Throwable {
      withDevice(BasicWebAuthnClientTests::testMakeCredentialGetAssertion);
    }

    @Test
    @Category(SmokeTest.class)
    public void testCancelMakeCredential() throws Throwable {
      withDevice(BasicWebAuthnClientTests::testCancelMakeCredential);
    }

    @Test
    public void testMakeCredentialGetAssertionTokenUvOnly() throws Throwable {
      withDevice(BasicWebAuthnClientTests::testMakeCredentialGetAssertionTokenUvOnly);
    }

    @Test
    public void testGetAssertionMultipleUsersRk() throws Throwable {
      withDevice(BasicWebAuthnClientTests::testGetAssertionMultipleUsersRk);
    }

    @Test
    public void testGetAssertionWithAllowList() throws Throwable {
      withDevice(BasicWebAuthnClientTests::testGetAssertionWithAllowList);
    }

    @Test
    public void testMakeCredentialWithExcludeList() throws Throwable {
      withDevice(BasicWebAuthnClientTests::testMakeCredentialWithExcludeList);
    }

    @Test
    public void testMakeCredentialKeyAlgorithms() throws Throwable {
      withDevice(BasicWebAuthnClientTests::testMakeCredentialKeyAlgorithms);
    }

    @Test
    public void testClientPinManagement() throws Throwable {
      withDevice(BasicWebAuthnClientTests::testClientPinManagement);
    }

    @Test
    public void testClientCredentialManagement() throws Throwable {
      withDevice(BasicWebAuthnClientTests::testClientCredentialManagement);
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

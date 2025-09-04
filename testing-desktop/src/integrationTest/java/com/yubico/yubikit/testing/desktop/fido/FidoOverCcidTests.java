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

import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.testing.desktop.PinUvAuthProtocolV1Test;
import com.yubico.yubikit.testing.desktop.SmokeTest;
import com.yubico.yubikit.testing.desktop.framework.FidoInstrumentedTests;
import com.yubico.yubikit.testing.fido.BasicWebAuthnClientTests;
import java.util.Collections;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  FidoOverCcidTests.NoScpTests.class,
  FidoOverCcidTests.Scp11bTests.class,
})
public class FidoOverCcidTests {
  public static class NoScpTests extends FidoInstrumentedTests {

    @Before
    public void setupCcidOnly() {
      connectionTypes = Collections.singletonList(SmartCardConnection.class);
    }

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
    @Category(SmokeTest.class)
    public void testSwitchTransports() throws Throwable {
      withDevice(BasicWebAuthnClientTests::testCancelMakeCredential);
      connectionTypes = Collections.singletonList(FidoConnection.class);
      withDevice(BasicWebAuthnClientTests::testCancelMakeCredential);
      connectionTypes = Collections.singletonList(SmartCardConnection.class);
      withDevice(BasicWebAuthnClientTests::testCancelMakeCredential);
      connectionTypes = Collections.singletonList(FidoConnection.class);
      withDevice(BasicWebAuthnClientTests::testCancelMakeCredential);
    }
  }

  @Category(PinUvAuthProtocolV1Test.class)
  public static class Scp11bTests extends NoScpTests {
    @Override
    protected Byte getScpKid() {
      return ScpKid.SCP11b;
    }
  }
}

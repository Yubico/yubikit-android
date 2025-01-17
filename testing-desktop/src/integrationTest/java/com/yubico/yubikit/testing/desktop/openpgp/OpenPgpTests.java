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
package com.yubico.yubikit.testing.desktop.openpgp;

import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.testing.desktop.SlowTest;
import com.yubico.yubikit.testing.desktop.SmokeTest;
import com.yubico.yubikit.testing.desktop.framework.OpenPgpInstrumentedTests;
import com.yubico.yubikit.testing.openpgp.OpenPgpDeviceTests;
import org.jetbrains.annotations.Nullable;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  OpenPgpTests.NoScpTests.class,
  OpenPgpTests.Scp11bTests.class,
})
public class OpenPgpTests {
  public static class NoScpTests extends OpenPgpInstrumentedTests {
    @Test
    public void testImportRsaKeys() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testImportRsaKeys);
    }

    @Test
    public void testImportEcDsaKeys() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testImportEcDsaKeys);
    }

    @Test
    public void testImportEd25519Keys() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testImportEd25519);
    }

    @Test
    public void testImportX25519Keys() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testImportX25519);
    }

    @Test
    public void testGenerateRequiresAdmin() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testGenerateRequiresAdmin);
    }

    @Test
    public void testChangePin() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testChangePin);
    }

    @Test
    public void testResetPin() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testResetPin);
    }

    @Test
    public void testSetPinAttempts() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testSetPinAttempts);
    }

    @Test
    @Category(SlowTest.class)
    public void testGenerateRsaKeys() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testGenerateRsaKeys);
    }

    @Test
    public void testGenerateEcKeys() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testGenerateEcKeys);
    }

    @Test
    public void testGenerateEd25519() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testGenerateEd25519);
    }

    @Test
    public void testGenerateX25519() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testGenerateX25519);
    }

    @Test
    public void testAttestation() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testAttestation);
    }

    @Test
    @Category(SmokeTest.class)
    public void testSigPinPolicy() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testSigPinPolicy);
    }

    @Test
    public void testKdf() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testKdf);
    }

    @Test
    public void testUnverifyPin() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testUnverifyPin);
    }

    @Test
    public void testDeleteKey() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testDeleteKey);
    }

    @Test
    public void testCertificateManagement() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testCertificateManagement);
    }

    @Test
    @Category(SmokeTest.class)
    public void testGetChallenge() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testGetChallenge);
    }

    @Test
    public void testSetUif() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testSetUif);
    }

    @Test
    public void testPinComplexity() throws Throwable {
      withOpenPgpSession(OpenPgpDeviceTests::testPinComplexity);
    }
  }

  public static class Scp11bTests extends NoScpTests {
    @Nullable
    @Override
    protected Byte getScpKid() {
      return ScpKid.SCP11b;
    }
  }
}

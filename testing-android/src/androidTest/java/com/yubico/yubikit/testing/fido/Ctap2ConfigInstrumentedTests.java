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

import com.yubico.yubikit.testing.AlwaysManualTest;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;
import org.junit.Test;
import org.junit.experimental.categories.Categories;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * Config tests.
 *
 * <p>These tests will change FIDO2 application configuration through authenticatorConfig. As these
 * changes are irreversible.
 *
 * <p>Read documentation for each test for more information.
 */
@RunWith(Categories.class)
@Suite.SuiteClasses(Ctap2ConfigInstrumentedTests.ConfigTests.class)
@Categories.ExcludeCategory(AlwaysManualTest.class)
public class Ctap2ConfigInstrumentedTests {

  public static class ConfigTests extends FidoInstrumentedTests {
    @Test
    public void testReadWriteEnterpriseAttestation() throws Throwable {
      withCtap2Session(Ctap2ConfigTests::testReadWriteEnterpriseAttestation);
    }

    /**
     * Toggles the {@code alwaysUv} option to opposite value. It is not possible to set this option
     * to `false` on a FIPS approved YubiKey.
     *
     * @throws Throwable if an error occurs
     */
    @Test
    @Category(AlwaysManualTest.class)
    public void testToggleAlwaysUv() throws Throwable {
      withCtap2Session(Ctap2ConfigTests::testToggleAlwaysUv);
    }

    /**
     * Sets the {@code forcePinChange} flag, verifies that and then changes the PIN twice so that
     * the device uses the {@code TestUtil.PIN}.
     *
     * @throws Throwable if an error occurs
     */
    @Test
    public void testSetForcePinChange() throws Throwable {
      withCtap2Session(Ctap2ConfigTests::testSetForcePinChange);
    }

    /**
     * Changes the {@code minPinLength} value. This change is irreversible and after running this
     * test, the YubiKey should be reset.
     *
     * @throws Throwable if an error occurs
     */
    @Test
    @Category(AlwaysManualTest.class)
    public void testSetMinPinLength() throws Throwable {
      withCtap2Session(Ctap2ConfigTests::testSetMinPinLength);
    }
  }
}

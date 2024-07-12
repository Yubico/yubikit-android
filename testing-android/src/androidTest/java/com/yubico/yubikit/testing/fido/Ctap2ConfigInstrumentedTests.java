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

import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;

import org.junit.Test;

/**
 * NOTE: Run the testcases in this suite manually one by one. See test case documentation
 * and reset the FIDO application where needed.
 */
public class Ctap2ConfigInstrumentedTests extends FidoInstrumentedTests {

    @Test
    public void testReadWriteEnterpriseAttestation() throws Throwable {
        withCtap2Session(Ctap2ConfigTests::testReadWriteEnterpriseAttestation);
    }

    @Test
    public void testToggleAlwaysUv() throws Throwable {
        withCtap2Session(Ctap2ConfigTests::testToggleAlwaysUv);
    }

    /**
     * Reset the FIDO application after calling this test case.
     *
     * @throws Throwable on any error
     */
    @Test
    public void testSetForcePinChange() throws Throwable {
        withCtap2Session(Ctap2ConfigTests::testSetForcePinChange);
    }

    /**
     * Reset the FIDO application after calling this test case.
     *
     * @throws Throwable on any error
     */
    @Test
    public void testSetMinPinLength() throws Throwable {
        withCtap2Session(Ctap2ConfigTests::testSetMinPinLength);
    }
}

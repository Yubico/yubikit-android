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

import androidx.test.filters.LargeTest;

import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;

import org.junit.Test;

/**
 * NOTE: Run the testcases in this suite manually one by one. See test case documentation
 * and reset the FIDO application where needed.
 */
@LargeTest
public class Ctap2ConfigInstrumentedTests extends FidoInstrumentedTests {

    @Test
    public void testReadWriteEnterpriseAttestation() throws Throwable {
        withCtap2Session(
                "Device has no support for EnterpriseAttestation",
                (ignoredDevice, session) -> session.getInfo().getOptions().containsKey("ep"),
                Ctap2ConfigTests::testReadWriteEnterpriseAttestation,
                new PinUvAuthProtocolV2()
        );
    }

    @Test
    public void testToggleAlwaysUv() throws Throwable {
        withCtap2Session(
                "Device has no support for alwaysUV",
                (ignoredDevice, session) -> session.getInfo().getOptions().containsKey("alwaysUv"),
                Ctap2ConfigTests::testToggleAlwaysUv,
                new PinUvAuthProtocolV2()
        );
    }

    /**
     * Reset the FIDO application after calling this test case.
     *
     * @throws Throwable on any error
     */
    @Test
    public void testSetForcePinChange() throws Throwable {
        withCtap2Session(
                Ctap2ConfigTests::testSetForcePinChange,
                new PinUvAuthProtocolV2()
        );
    }

    /**
     * Reset the FIDO application after calling this test case.
     *
     * @throws Throwable on any error
     */
    @Test
    public void testSetMinPinLength() throws Throwable {
        withCtap2Session(
                Ctap2ConfigTests::testSetMinPinLength,
                new PinUvAuthProtocolV2()
        );
    }
}

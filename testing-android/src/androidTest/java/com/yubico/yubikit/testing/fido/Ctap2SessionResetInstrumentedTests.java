/*
 * Copyright (C) 2023 Yubico.
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

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;

import org.junit.Test;

import java.util.Map;

/**
 * Tests FIDO Reset.
 * <p>
 * Notes:
 * <ul>
 *     <li>The tests for different protocols are meant to be ran separately.</li>
 *     <li>Before running any of the tests, disconnect the security Key from the device</li>
 *     <li>Bio devices are currently ignored.</li>
 * </ul>
 */
public class Ctap2SessionResetInstrumentedTests extends FidoInstrumentedTests {

    /**
     * @noinspection BooleanMethodIsAlwaysInverted
     */
    private static boolean supportsBioEnroll(Ctap2Session session) {
        final Map<String, ?> options = session.getCachedInfo().getOptions();
        return options.containsKey("bioEnroll");
    }

    @Test
    public void testReset() throws Throwable {
        withCtap2Session(
                "Skipping reset test - authenticator supports bio enrollment",
                (device, session) -> !supportsBioEnroll(session),
                Ctap2SessionTests::testReset
        );
    }
}

/*
 * Copyright (C) 2022-2023 Yubico.
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

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.testing.PinComplexityDeviceTests;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;

import org.junit.Test;

import java.util.List;

@LargeTest
public class Ctap2ClientPinInstrumentedTests extends FidoInstrumentedTests {

    public static boolean supportsPinUvAuthProtocol(
            Ctap2Session session,
            PinUvAuthProtocol pinUvAuthProtocol) {
        return supportsPinUvAuthProtocol(session, pinUvAuthProtocol.getVersion());
    }

    public static boolean supportsPinUvAuthProtocol(
            Ctap2Session session,
            int pinUvAuthProtocolVersion) {
        final List<Integer> pinUvAuthProtocols =
                session.getCachedInfo().getPinUvAuthProtocols();
        return pinUvAuthProtocols.contains(pinUvAuthProtocolVersion);
    }

    @Test
    public void testSetPinProtocolV1() throws Throwable {
        withCtap2Session(
                Ctap2ClientPinTests::testSetPinProtocol,
                new PinUvAuthProtocolV1()
        );
    }

    @Test
    public void testPinComplexityPin() throws Throwable {
        withCtap2Session(
                PinComplexityDeviceTests::testFidoPinComplexity);
    }

    @Test
    public void testSetPinProtocolV2() throws Throwable {
        final PinUvAuthProtocol pinUvAuthProtocol = new PinUvAuthProtocolV2();
        withCtap2Session(
                "PIN/UV Auth Protocol not supported",
                (device, session) -> supportsPinUvAuthProtocol(
                        session,
                        pinUvAuthProtocol),
                Ctap2ClientPinTests::testSetPinProtocol,
                pinUvAuthProtocol
        );
    }
}

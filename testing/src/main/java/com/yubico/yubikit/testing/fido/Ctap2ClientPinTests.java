/*
 * Copyright (C) 2020-2024 Yubico.
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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;

import java.io.IOException;
import java.util.Objects;

public class Ctap2ClientPinTests {
    /**
     * Attempts to set (or verify) the default PIN, or fails.
     */
    static void ensureDefaultPinSet(Ctap2Session session) throws IOException, CommandException {

        Ctap2Session.InfoData info = session.getInfo();

        ClientPin pin = new ClientPin(session, TestData.PIN_UV_AUTH_PROTOCOL);
        boolean pinSet = Objects.requireNonNull((Boolean) info.getOptions().get("clientPin"));

        if (!pinSet) {
            pin.setPin(TestData.PIN);
        } else {
            pin.getPinToken(
                    TestData.PIN,
                    ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA,
                    "localhost");
        }
    }

    public static void testClientPin(Ctap2Session session) throws Throwable {
        char[] otherPin = "12312312".toCharArray();

        Integer permissions = ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA;
        String permissionRpId = "localhost";

        // ensureDefaultPinSet(session);

        ClientPin pin = new ClientPin(session, TestData.PIN_UV_AUTH_PROTOCOL);
        assertThat(pin.getPinUvAuth().getVersion(), is(TestData.PIN_UV_AUTH_PROTOCOL.getVersion()));
        assertThat(pin.getPinRetries().getCount(), is(8));

        pin.changePin(TestData.PIN, otherPin);
        try {
            pin.getPinToken(TestData.PIN, permissions, permissionRpId);
            fail("Wrong PIN was accepted");
        } catch (CtapException e) {
            assertThat(e.getCtapError(), is(CtapException.ERR_PIN_INVALID));

        }
        assertThat(pin.getPinRetries().getCount(), is(7));

        assertThat(pin.getPinToken(otherPin, permissions, permissionRpId), notNullValue());
        assertThat(pin.getPinRetries().getCount(), is(8));
        pin.changePin(otherPin, TestData.PIN);
    }
}

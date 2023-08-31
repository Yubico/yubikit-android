/*
 * Copyright (C) 2020-2023 Yubico.
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
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;

import java.io.IOException;
import java.util.Objects;

public class Ctap2ClientPinTests {
    /**
     * Attempts to set (or verify) the default PIN, or fails.
     */
    static void ensureDefaultPinSet(Ctap2Session session) throws IOException, CommandException {
        ClientPin pin = new ClientPin(session, new PinUvAuthProtocolV1());
        boolean pinSet = Objects.requireNonNull((Boolean) session.getInfo().getOptions().get("clientPin"));

        if (!pinSet) {
            pin.setPin(TestData.PIN);
        } else {
            pin.getPinToken(TestData.PIN);
        }
    }

    public static void testSetPinProtocol(Ctap2Session ctap2) throws Throwable {
        char[] otherPin = "123123".toCharArray();

        ensureDefaultPinSet(ctap2);

        ClientPin pin = new ClientPin(ctap2, new PinUvAuthProtocolV1());
        assertThat(pin.getPinUvAuth().getVersion(), is(1));
        assertThat(pin.getPinRetries(), is(8));

        pin.changePin(TestData.PIN, otherPin);
        try {
            pin.getPinToken(TestData.PIN);
            fail("Wrong PIN was accepted");
        } catch (CtapException e) {
            assertThat(e.getCtapError(), is(CtapException.ERR_PIN_INVALID));

        }
        assertThat(pin.getPinRetries(), is(7));

        assertThat(pin.getPinToken(otherPin), notNullValue());
        assertThat(pin.getPinRetries(), is(8));
        pin.changePin(otherPin, TestData.PIN);
    }

}
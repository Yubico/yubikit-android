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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;
import static java.lang.Boolean.TRUE;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Config;
import com.yubico.yubikit.fido.ctap.Ctap2Session;

import java.io.IOException;

public class Ctap2ConfigTests {

    static Config getConfig(Ctap2Session session) throws IOException, CommandException {
        ClientPin clientPin = new ClientPin(session, TestData.PIN_UV_AUTH_PROTOCOL);
        byte[] pinToken = clientPin.getPinToken(TestData.PIN, ClientPin.PIN_PERMISSION_ACFG, null);
        return new Config(session, TestData.PIN_UV_AUTH_PROTOCOL, pinToken);
    }

    public static void testReadWriteEnterpriseAttestation(Ctap2Session session) throws Throwable {
        assumeTrue("Enterprise attestation not supported",
                session.getInfo().getOptions().containsKey("ep"));
        Config config = getConfig(session);
        config.enableEnterpriseAttestation();
        assertSame(TRUE, session.getInfo().getOptions().get("ep"));
    }

    public static void testToggleAlwaysUv(Ctap2Session session) throws Throwable {
        assumeTrue("Device does not support alwaysUv",
                session.getInfo().getOptions().containsKey("alwaysUv"));
        Config config = getConfig(session);
        Object alwaysUv = getAlwaysUv(session);
        config.toggleAlwaysUv();
        assertNotSame(getAlwaysUv(session), alwaysUv);
    }

    public static void testSetForcePinChange(Ctap2Session session) throws Throwable {
        assumeTrue("authenticatorConfig not supported",
                Config.isSupported(session.getCachedInfo()));
        assumeFalse("Force PIN change already set. Reset key and retry", session.getInfo().getForcePinChange());
        Config config = getConfig(session);
        config.setMinPinLength(null, null, true);
        assertTrue(session.getInfo().getForcePinChange());

        // set a new PIN
        ClientPin pin = new ClientPin(session, TestData.PIN_UV_AUTH_PROTOCOL);
        assertThat(pin.getPinUvAuth().getVersion(), is(TestData.PIN_UV_AUTH_PROTOCOL.getVersion()));
        assertThat(pin.getPinRetries().getCount(), is(8));

        pin.changePin(TestData.PIN, TestData.OTHER_PIN);
        assertFalse(session.getInfo().getForcePinChange());

        // set to a default PIN
        pin.changePin(TestData.OTHER_PIN, TestData.PIN);
        assertFalse(session.getInfo().getForcePinChange());

    }

    public static void testSetMinPinLength(Ctap2Session session) throws Throwable {
        assumeTrue("authenticatorConfig not supported",
                Config.isSupported(session.getCachedInfo()));
        Config config = getConfig(session);
        // after calling this the key must be reset to get the default min pin length value
        config.setMinPinLength(50, null, null);
        assertEquals(50, session.getInfo().getMinPinLength());
    }

    static boolean getAlwaysUv(Ctap2Session session) throws IOException, CommandException {
        return session.getInfo().getOptions().get("alwaysUv") == TRUE;
    }
}
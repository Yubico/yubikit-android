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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static java.lang.Boolean.TRUE;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Config;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;

import java.io.IOException;

public class Ctap2ConfigTests {

    static Config getConfig(Ctap2Session session, PinUvAuthProtocol pinUvAuthProtocol) throws IOException, CommandException {
        Ctap2ClientPinTests.ensureDefaultPinSet(session, pinUvAuthProtocol);
        ClientPin clientPin = new ClientPin(session, pinUvAuthProtocol);
        byte[] pinToken = clientPin.getPinToken(TestData.PIN, ClientPin.PIN_PERMISSION_ACFG, null);
        return new Config(session, pinUvAuthProtocol, pinToken);
    }

    public static void testReadWriteEnterpriseAttestation(Ctap2Session session, Object... args) throws Throwable {
        Config config = getConfig(session, Ctap2ClientPinTests.getPinUvAuthProtocol(args));
        config.enableEnterpriseAttestation();
        assertSame(TRUE, session.getInfo().getOptions().get("ep"));
    }

    public static void testToggleAlwaysUv(Ctap2Session session, Object... args) throws Throwable {
        Config config = getConfig(session, Ctap2ClientPinTests.getPinUvAuthProtocol(args));
        Object alwaysUv = getAlwaysUv(session);
        config.toggleAlwaysUv();
        assertNotSame(getAlwaysUv(session), alwaysUv);
    }

    public static void testSetForcePinChange(Ctap2Session session, Object... args) throws Throwable {
        assertFalse(session.getInfo().getForcePinChange());
        Config config = getConfig(session, Ctap2ClientPinTests.getPinUvAuthProtocol(args));
        config.setMinPinLength(null, null, true);
        assertTrue(session.getInfo().getForcePinChange());
    }

    public static void testSetMinPinLength(Ctap2Session session, Object... args) throws Throwable {
        Config config = getConfig(session, Ctap2ClientPinTests.getPinUvAuthProtocol(args));
        // after calling this the key must be reset to get the default min pin length value
        config.setMinPinLength(50, null, null);
        assertEquals(50, session.getInfo().getMinPinLength());
    }

    static boolean getAlwaysUv(Ctap2Session session) throws IOException, CommandException {
        return session.getInfo().getOptions().get("alwaysUv") == TRUE;
    }
}
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
package com.yubico.yubikit.testing;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;
import com.yubico.yubikit.support.DeviceUtil;
import com.yubico.yubikit.testing.piv.PivTestUtils;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assume;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Objects;

public class MultiProtocolResetDeviceTests {

    /**
     * Verifies that this is a Bio multi-protocol device and resets it
     */
    public static void setupDevice(YubiKeyDevice device) throws IOException, CommandException {
        checkDevice(device);
        resetDevice(device);

        assertFalse(isPivResetBlocked(device));
        assertFalse(isFidoResetBlocked(device));
    }

    public static void testSettingPivPinBlocksFidoReset(YubiKeyDevice device) throws IOException, CommandException {
        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            PivSession piv = new PivSession(connection);
            piv.changePin("123456".toCharArray(), "multipin".toCharArray());

            assertFalse(isPivResetBlocked(device));
            assertTrue(isFidoResetBlocked(device));
        }
    }

    public static void testPivOperationBlocksFidoReset(YubiKeyDevice device) throws IOException, CommandException {
        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            PivSession piv = new PivSession(connection);
            KeyPair rsaKeyPair = PivTestUtils.loadKey(KeyType.RSA1024);
            piv.authenticate(Hex.decode("010203040506070801020304050607080102030405060708"));
            piv.putKey(Slot.RETIRED1, PrivateKeyValues.fromPrivateKey(rsaKeyPair.getPrivate()), PinPolicy.DEFAULT, TouchPolicy.DEFAULT);

            assertFalse(isPivResetBlocked(device));
            assertTrue(isFidoResetBlocked(device));
        }
    }

    public static void testSettingFidoPinBlocksPivReset(YubiKeyDevice device) throws IOException, CommandException {
        try (FidoConnection connection = device.openConnection(FidoConnection.class)) {
            Ctap2Session ctap2 = new Ctap2Session(connection);

            PinUvAuthProtocol pinUvAuthProtocol = new PinUvAuthProtocolV2();
            // note that max PIN length is 8 because it is shared with PIV
            char[] defaultPin = "11234567".toCharArray();

            Ctap2Session.InfoData info = ctap2.getCachedInfo();
            ClientPin pin = new ClientPin(ctap2, pinUvAuthProtocol);
            boolean pinSet = Objects.requireNonNull((Boolean) info.getOptions().get("clientPin"));
            assertFalse(pinSet);
            pin.setPin(defaultPin);

            assertTrue(isPivResetBlocked(device));
            assertFalse(isFidoResetBlocked(device));
        }
    }

    private static void checkDevice(YubiKeyDevice device) throws IOException, CommandException {
        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            ManagementSession management = new ManagementSession(connection);
            DeviceInfo deviceInfo = management.getDeviceInfo();
            String name = DeviceUtil.getName(deviceInfo, null);
            Assume.assumeTrue("This device (" + name + ") is not suitable for this test",
                    name.equals("YubiKey Bio - Multi-protocol Edition") ||
                            name.equals("YubiKey C Bio - Multi-protocol Edition"));
        }
    }

    private static void resetDevice(YubiKeyDevice device) throws IOException, CommandException {
        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            ManagementSession management = new ManagementSession(connection);
            management.deviceReset();
        }
    }

    private static int getResetBlocked(YubiKeyDevice device) throws IOException, CommandException {
        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            ManagementSession managementSession = new ManagementSession(connection);
            DeviceInfo deviceInfo = managementSession.getDeviceInfo();
            return deviceInfo.getResetBlocked();
        }
    }

    private static boolean isPivResetBlocked(YubiKeyDevice device) throws IOException, CommandException {
        int resetBlocked = getResetBlocked(device);
        return (resetBlocked & Capability.PIV.bit) == Capability.PIV.bit;
    }

    private static boolean isFidoResetBlocked(YubiKeyDevice device) throws IOException, CommandException {
        int resetBlocked = getResetBlocked(device);
        return (resetBlocked & Capability.FIDO2.bit) == Capability.FIDO2.bit;
    }

}

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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.fido.client.BasicWebAuthnClient;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.client.CredentialManager;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Config;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.ManagementSession;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class FidoTestUtils {

    /**
     * Prepares the device for a test and sets variables in {@link TestData}. If {@code setPin}
     * is true, then sets the FIDO2 PIN, verifies FIPS approval state and removes existing
     * credentials.
     *
     * @param device The YubiKey which should be setup for a test.
     * @param pinUvAuthProtocol Pin UV/Auth protocol to use during the test.
     * @param setPin Whether a FIDO2 PIN should be set. Several tests need a device without a PIN.
     *
     * @throws Throwable if an error occurred
     */
    public static void verifyAndSetup(
            YubiKeyDevice device,
            PinUvAuthProtocol pinUvAuthProtocol,
            boolean setPin)
            throws Throwable {

        boolean isFidoFipsCapable;

        try (YubiKeyConnection connection = openConnection(device)) {

            ManagementSession managementSession = getManagementSession(connection);
            DeviceInfo deviceInfo = managementSession.getDeviceInfo();
            assertNotNull(deviceInfo);

            isFidoFipsCapable =
                    (deviceInfo.getFipsCapable() & Capability.FIDO2.bit) == Capability.FIDO2.bit;

            Ctap2Session session = getCtap2Session(connection);
            assumeTrue(
                    "PIN UV Protocol not supported",
                    supportsPinUvAuthProtocol(session, pinUvAuthProtocol));

            if (isFidoFipsCapable) {
                assumeTrue("Ignoring FIPS tests which don't use PinUvAuthProtocolV2",
                        pinUvAuthProtocol.getVersion() == 2);
            }

            TestData.PIN_UV_AUTH_PROTOCOL = pinUvAuthProtocol;
            TestData.TRANSPORT_USB = device.getTransport() == Transport.USB;

            if (setPin) {
                verifyOrSetPin(session);
            }

            if (isFidoFipsCapable &&
                    Boolean.FALSE.equals(session.getInfo().getOptions().get("alwaysUv"))) {
                // set always UV on
                Config config = Ctap2ConfigTests.getConfig(session);
                config.toggleAlwaysUv();
            }

            managementSession = getManagementSession(connection);
            deviceInfo = managementSession.getDeviceInfo();
            TestData.FIPS_APPROVED =
                    (deviceInfo.getFipsApproved() & Capability.FIDO2.bit) == Capability.FIDO2.bit;

            // after changing the user and admin PINs, we expect a FIPS capable device
            // to be FIPS approved
            if (setPin && isFidoFipsCapable) {
                assertNotNull(deviceInfo);
                assertTrue("Device not FIDO FIPS approved as expected", TestData.FIPS_APPROVED);
            }

            // remove existing credentials
            if (setPin) {
                // cannot use CredentialManager if there is no PIN set
                deleteExistingCredentials(session);
            }
        }
    }

    private static boolean supportsPinUvAuthProtocol(
            Ctap2Session session,
            PinUvAuthProtocol pinUvAuthProtocol) {
        final List<Integer> pinUvAuthProtocols = session.getCachedInfo().getPinUvAuthProtocols();
        return pinUvAuthProtocols.contains(pinUvAuthProtocol.getVersion());
    }

    private static YubiKeyConnection openConnection(YubiKeyDevice device) throws IOException {
        if (device.supportsConnection(FidoConnection.class)) {
            return device.openConnection(FidoConnection.class);
        }
        if (device.supportsConnection(SmartCardConnection.class)) {
            return device.openConnection(SmartCardConnection.class);
        }
        throw new IllegalArgumentException("Device does not support FIDO or SmartCard connection");
    }

    private static Ctap2Session getCtap2Session(YubiKeyConnection connection)
            throws IOException, CommandException {
        Ctap2Session session = (connection instanceof FidoConnection)
                ? new Ctap2Session((FidoConnection) connection)
                : connection instanceof SmartCardConnection
                ? new Ctap2Session((SmartCardConnection) connection)
                : null;

        if (session == null) {
            throw new IllegalArgumentException("Connection does not support Ctap2Session");
        }

        return session;
    }

    private static ManagementSession getManagementSession(YubiKeyConnection connection) throws IOException, CommandException {
        ManagementSession session = (connection instanceof FidoConnection)
                ? new ManagementSession((FidoConnection) connection)
                : connection instanceof SmartCardConnection
                ? new ManagementSession((SmartCardConnection) connection)
                : null;

        if (session == null) {
            throw new IllegalArgumentException("Connection does not support ManagementSession");
        }

        return session;
    }

    private static void deleteExistingCredentials(Ctap2Session session)
            throws IOException, CommandException, ClientError {
        final BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
        final CredentialManager credentialManager = webauthn.getCredentialManager(TestData.PIN);
        final List<String> rpIds = credentialManager.getRpIdList();
        for (String rpId : rpIds) {
            Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> credentials
                    = credentialManager.getCredentials(rpId);
            for (PublicKeyCredentialDescriptor credential : credentials.keySet()) {
                credentialManager.deleteCredential(credential);
            }
        }
        assertEquals("Failed to remove all credentials", 0, credentialManager.getCredentialCount());
    }

    /**
     * Attempts to set (or verify) the default PIN, or fails.
     */
    private static void verifyOrSetPin(Ctap2Session session) throws IOException, CommandException {

        Ctap2Session.InfoData info = session.getInfo();

        ClientPin pin = new ClientPin(session, TestData.PIN_UV_AUTH_PROTOCOL);
        boolean pinSet = Objects.requireNonNull((Boolean) info.getOptions().get("clientPin"));

        try {
            if (!pinSet) {
                pin.setPin(TestData.PIN);
            } else {
                pin.getPinToken(
                        TestData.PIN,
                        ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA,
                        "localhost");
            }
        } catch (CommandException e) {
            fail("YubiKey cannot be used for test, failed to set/verify PIN. Please reset " +
                    "and try again.");
        }
    }
}

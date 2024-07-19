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

import static com.yubico.yubikit.testing.TestUtils.getCtap2Session;
import static com.yubico.yubikit.testing.TestUtils.openConnection;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.client.BasicWebAuthnClient;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.client.CredentialManager;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Config;
import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.support.DeviceUtil;
import com.yubico.yubikit.testing.TestState;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nullable;

public class FidoTestState extends TestState {

    private final PinUvAuthProtocol pinUvAuthProtocol;
    private final boolean isFipsApproved;
    public Boolean alwaysUv = false;

    public FidoTestState(
            YubiKeyDevice device,
            ReconnectDeviceCallback reconnect,
            @Nullable Byte scpKid,
            PinUvAuthProtocol pinUvAuthProtocol,
            boolean setPin)
            throws Throwable {
        super(device, reconnect, scpKid);

        boolean isFidoFipsCapable = false;
        DeviceInfo deviceInfo = null;

        try (YubiKeyConnection connection = openConnection(device)) {
            try {
                deviceInfo = DeviceUtil.readInfo(connection, null);
                assertNotNull(deviceInfo);
                isFidoFipsCapable =
                        (deviceInfo.getFipsCapable() & Capability.FIDO2.bit) == Capability.FIDO2.bit;

                assumeTrue("This YubiKey does not support FIDO2",
                        deviceInfo.getVersion().isAtLeast(5, 0, 0));
            } catch (IllegalArgumentException ignored) {
                // failed to get device info, this is not a YubiKey
            }

            Ctap2Session session = getCtap2Session(connection, scpParameters);
            assumeTrue(
                    "PIN UV Protocol not supported",
                    supportsPinUvAuthProtocol(session, pinUvAuthProtocol));

            if (isFidoFipsCapable) {
                assumeTrue("Ignoring FIPS tests which don't use PinUvAuthProtocolV2",
                        pinUvAuthProtocol.getVersion() == 2);
            }

            this.pinUvAuthProtocol = pinUvAuthProtocol;

            if (setPin) {
                verifyOrSetPin(session);
            }

            this.alwaysUv = (Boolean) session.getInfo().getOptions().get("alwaysUv");
            if (isFidoFipsCapable && Boolean.FALSE.equals(this.alwaysUv)) {
                // set always UV on
                Config config = Ctap2ConfigTests.getConfig(session, this);
                config.toggleAlwaysUv();
                this.alwaysUv = true;
            }

            boolean fipsApproved = false;

            try {
                deviceInfo = DeviceUtil.readInfo(connection, null);
                fipsApproved =
                        (deviceInfo.getFipsApproved() & Capability.FIDO2.bit) == Capability.FIDO2.bit;
            } catch (IllegalArgumentException ignored) {
                // not a YubiKey
            }

            this.isFipsApproved = fipsApproved;

            // after changing the PIN and setting alwaysUv, we expect a FIPS capable device
            // to be FIPS approved
            if (setPin && isFidoFipsCapable) {
                assertNotNull(deviceInfo);
                assertTrue("Device not FIDO FIPS approved as expected", this.isFipsApproved);
            }

            // remove existing credentials
            if (setPin) {
                // cannot use CredentialManager if there is no PIN set
                session = getCtap2Session(connection, scpParameters);
                deleteExistingCredentials(session);
            }
        }
    }

    public boolean isFipsApproved() {
        return isFipsApproved;
    }

    public PinUvAuthProtocol getPinUvAuthProtocol() {
        return pinUvAuthProtocol;
    }

    boolean supportsPinUvAuthProtocol(
            Ctap2Session session,
            PinUvAuthProtocol pinUvAuthProtocol) {
        final List<Integer> pinUvAuthProtocols = session.getCachedInfo().getPinUvAuthProtocols();
        return pinUvAuthProtocols.contains(pinUvAuthProtocol.getVersion());
    }

    void deleteExistingCredentials(Ctap2Session session)
            throws IOException, CommandException, ClientError {
        final BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
        if (!CredentialManagement.isSupported(session.getCachedInfo())) {
            return;
        }
        CredentialManager credentialManager = webauthn.getCredentialManager(TestData.PIN);
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
    void verifyOrSetPin(Ctap2Session session) throws IOException, CommandException {

        Ctap2Session.InfoData info = session.getInfo();

        ClientPin pin = new ClientPin(session, pinUvAuthProtocol);
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

    public void withDeviceCallback(StatefulDeviceCallback<FidoTestState> callback) throws Throwable {
        callback.invoke(this);
    }

    public void withCtap2(SessionCallback<Ctap2Session> callback) throws Throwable {
        try (YubiKeyConnection connection = openConnection(currentDevice)) {
            callback.invoke(getCtap2Session(connection, scpParameters));
        }
        reconnect();
    }

    public void withCtap2(StatefulSessionCallback<Ctap2Session, FidoTestState> callback) throws Throwable {
        try (YubiKeyConnection connection = openConnection(currentDevice)) {
            callback.invoke(getCtap2Session(connection, scpParameters), (FidoTestState) this);
        }
        reconnect();
    }

    public <T> T withCtap2(SessionCallbackT<Ctap2Session, T> callback) throws Throwable {
        T result;
        try (YubiKeyConnection connection = openConnection(currentDevice)) {
            result = callback.invoke(getCtap2Session(connection, scpParameters));
        }
        reconnect();
        return result;
    }

}

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

package com.yubico.yubikit.testing.oath;

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.oath.OathSession;
import com.yubico.yubikit.testing.ScpParameters;
import com.yubico.yubikit.testing.TestState;

import java.io.IOException;

import javax.annotation.Nullable;

public class OathTestState extends TestState {
    public boolean isFipsApproved;
    public char[] password;

    public static class Builder extends TestState.Builder<OathTestState.Builder> {

        public Builder(YubiKeyDevice device, UsbPid usbPid) {
            super(device, usbPid);
        }

        @Override
        public Builder getThis() {
            return this;
        }

        public OathTestState build() throws Throwable {
            return new OathTestState(this);
        }
    }

    protected OathTestState(OathTestState.Builder builder) throws Throwable {
        super(builder);

        password = "".toCharArray();

        boolean isOathFipsCapable = isFipsCapable(Capability.OATH);

        if (scpParameters.getKid() == null && isOathFipsCapable) {
            assumeTrue("Trying to use OATH FIPS capable device over NFC without SCP", isUsbTransport());
        }

        if (scpParameters.getKid() != null) {
            // skip the test if the connected key does not provide matching SCP keys
            assumeTrue(
                    "No matching key params found for required kid",
                    scpParameters.getKeyParams() != null
            );
        }

        try (SmartCardConnection connection = openSmartCardConnection()) {
            assumeTrue("Smart card not available", connection != null);

            OathSession oath = getOathSession(connection, scpParameters);

            assumeTrue("OATH not available", oath != null);
            oath.reset();

            final char[] complexPassword = "11234567".toCharArray();
            oath.setPassword(complexPassword);
            password = complexPassword;
        }

        isFipsApproved = isFipsApproved(Capability.OATH);

        // after changing the OATH password, we expect a FIPS capable device to be FIPS approved
        if (isOathFipsCapable) {
            assertTrue("Device not OATH FIPS approved as expected", isFipsApproved);
        }
    }

    public void withDeviceCallback(StatefulDeviceCallback<OathTestState> callback) throws Throwable {
        callback.invoke(this);
    }

    public void withOath(StatefulSessionCallback<OathSession, OathTestState> callback)
            throws Throwable {
        try (SmartCardConnection connection = openSmartCardConnection()) {
            callback.invoke(getOathSession(connection, scpParameters), this);
        }
        reconnect();
    }

    public void withOath(SessionCallback<OathSession> callback) throws Throwable {
        try (SmartCardConnection connection = openSmartCardConnection()) {
            callback.invoke(getOathSession(connection, scpParameters));
        }
        reconnect();
    }

    @Nullable
    public static OathSession getOathSession(SmartCardConnection connection, ScpParameters scpParameters)
            throws IOException {
        try {
            return new OathSession(connection, scpParameters.getKeyParams());
        } catch (ApplicationNotAvailableException ignored) {
            // no OATH support
        }
        return null;
    }
}

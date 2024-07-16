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
package com.yubico.yubikit.testing.openpgp;

import static com.yubico.yubikit.testing.openpgp.OpenPgpTestState.ADMIN_PIN;
import static com.yubico.yubikit.testing.openpgp.OpenPgpTestState.USER_PIN;
import static com.yubico.yubikit.testing.openpgp.OpenPgpTestState.FIPS_APPROVED;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.openpgp.OpenPgpSession;
import com.yubico.yubikit.openpgp.Pw;
import com.yubico.yubikit.testing.ScpParameters;

import org.junit.Assume;

public class OpenPgpTestUtils {

    private static final char[] COMPLEX_USER_PIN = "112345678".toCharArray();
    private static final char[] COMPLEX_ADMIN_PIN = "112345678".toCharArray();

    public static void verifyAndSetup(YubiKeyDevice device, ScpParameters scpParameters) throws Throwable {

        OpenPgpTestState.USER_PIN = Pw.DEFAULT_USER_PIN;
        OpenPgpTestState.ADMIN_PIN = Pw.DEFAULT_ADMIN_PIN;

        boolean isOpenPgpFipsCapable;
        boolean hasPinComplexity;

        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            ManagementSession managementSession = new ManagementSession(connection);
            DeviceInfo deviceInfo = managementSession.getDeviceInfo();
            assertNotNull(deviceInfo);

            isOpenPgpFipsCapable =
                    (deviceInfo.getFipsCapable() & Capability.OPENPGP.bit) == Capability.OPENPGP.bit;
            hasPinComplexity = deviceInfo.getPinComplexity();
        }

        if (scpParameters.getKid() == null && isOpenPgpFipsCapable) {
            Assume.assumeTrue("Trying to use OpenPgp FIPS capable device over NFC without SCP",
                    device.getTransport() != Transport.NFC);
        }

        if (scpParameters.getKid() != null) {
            // skip the test if the connected key does not provide matching SCP keys
            Assume.assumeTrue(
                    "No matching key params found for required kid",
                    scpParameters.getKeyParams() != null
            );
        }

        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            OpenPgpSession openPgp = null;
            try {
                openPgp = new OpenPgpSession(connection, scpParameters.getKeyParams());
            } catch (ApplicationNotAvailableException ignored) {

            }

            assumeTrue("OpenPGP not available", openPgp != null);
            openPgp.reset();

            if (hasPinComplexity) {
                // only use complex pins if pin complexity is required
                openPgp.changeUserPin(USER_PIN, COMPLEX_USER_PIN);
                openPgp.changeAdminPin(ADMIN_PIN, COMPLEX_ADMIN_PIN);
                OpenPgpTestState.USER_PIN = COMPLEX_USER_PIN;
                OpenPgpTestState.ADMIN_PIN = COMPLEX_ADMIN_PIN;
            }

            ManagementSession managementSession = new ManagementSession(connection);
            DeviceInfo deviceInfo = managementSession.getDeviceInfo();

            FIPS_APPROVED = (deviceInfo.getFipsApproved() & Capability.OPENPGP.bit) == Capability.OPENPGP.bit;

            // after changing the user and admin PINs, we expect a FIPS capable device
            // to be FIPS approved
            if (isOpenPgpFipsCapable) {
                assertNotNull(deviceInfo);
                assertTrue("Device not OpenPgp FIPS approved as expected", FIPS_APPROVED);
            }
        }
    }
}

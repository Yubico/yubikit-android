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
import com.yubico.yubikit.oath.OathSession;
import com.yubico.yubikit.testing.ScpParameters;

public class OathTestUtils {

    public static void updateFipsApprovedValue(YubiKeyDevice device) throws Throwable {
        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            ManagementSession managementSession = new ManagementSession(connection);
            DeviceInfo deviceInfo = managementSession.getDeviceInfo();
            assertNotNull(deviceInfo);
            OathDeviceTests.FIPS_APPROVED =
                    (deviceInfo.getFipsApproved() & Capability.OATH.bit) == Capability.OATH.bit;
        }
    }

    public static void verifyAndSetup(YubiKeyDevice device, ScpParameters scpParameters) throws Throwable {

        OathDeviceTests.OATH_PASSWORD = "".toCharArray();

        boolean isOathFipsCapable;

        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            ManagementSession managementSession = new ManagementSession(connection);
            DeviceInfo deviceInfo = managementSession.getDeviceInfo();
            assertNotNull(deviceInfo);

            isOathFipsCapable =
                    (deviceInfo.getFipsCapable() & Capability.OATH.bit) == Capability.OATH.bit;
        }

        if (scpParameters.getKid() == null && isOathFipsCapable) {
            assumeTrue("Trying to use OATH FIPS capable device over NFC without SCP",
                    device.getTransport() != Transport.NFC);
        }

        if (scpParameters.getKid() != null) {
            // skip the test if the connected key does not provide matching SCP keys
            assumeTrue(
                    "No matching key params found for required kid",
                    scpParameters.getKeyParams() != null
            );
        }

        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            OathSession oath = null;
            try {
                oath = new OathSession(connection, scpParameters.getKeyParams());
            } catch (ApplicationNotAvailableException ignored) {

            }

            assumeTrue("OATH not available", oath != null);
            oath.reset();

            final char[] oathPassword = "112345678".toCharArray();
            oath.setPassword(oathPassword);
            OathDeviceTests.OATH_PASSWORD = oathPassword;
        }

        updateFipsApprovedValue(device);

        // after changing the OATH password, we expect a FIPS capable device to be FIPS approved
        if (isOathFipsCapable) {
            assertTrue("Device not OATH FIPS approved as expected", OathDeviceTests.FIPS_APPROVED);
        }
    }
}

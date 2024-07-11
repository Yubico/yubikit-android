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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.oath.OathSession;
import com.yubico.yubikit.testing.TestState;

import org.junit.Assume;

import javax.annotation.Nullable;

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

    public static void verifyAndSetup(YubiKeyDevice device, @Nullable Byte kid) throws Throwable {

        OathDeviceTests.OATH_PASSWORD = "".toCharArray();

        boolean isOathFipsCapable;

        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            ManagementSession managementSession = new ManagementSession(connection);
            DeviceInfo deviceInfo = managementSession.getDeviceInfo();
            assertNotNull(deviceInfo);

            isOathFipsCapable =
                    (deviceInfo.getFipsCapable() & Capability.OATH.bit) == Capability.OATH.bit;
        }

        if (kid == null && isOathFipsCapable) {
            Assume.assumeTrue("Trying to use OATH FIPS capable device over NFC without SCP",
                    device.getTransport() != Transport.NFC);
        }

        // don't read SCP params on non capable devices
        TestState.keyParams = (isOathFipsCapable && kid != null)
                ? TestState.readScpKeyParams(device, kid)
                : null;

        if (kid != null) {
            // skip the test if the connected key does not provide matching SCP keys
            Assume.assumeTrue(
                    "No matching key params found for required kid",
                    TestState.keyParams != null
            );
        }

        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            OathSession oath = new OathSession(connection, TestState.keyParams);

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

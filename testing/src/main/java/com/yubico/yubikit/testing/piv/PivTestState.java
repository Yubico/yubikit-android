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

package com.yubico.yubikit.testing.piv;

import static com.yubico.yubikit.testing.MpeUtils.isMpe;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.ManagementKeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.testing.TestState;

public class PivTestState extends TestState {

    static final char[] DEFAULT_PIN = "123456".toCharArray();
    static final char[] DEFAULT_PUK = "12345678".toCharArray();
    static final byte[] DEFAULT_MANAGEMENT_KEY = new byte[]{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    private static final char[] COMPLEX_PIN = "11234567".toCharArray();
    private static final char[] COMPLEX_PUK = "11234567".toCharArray();
    private static final byte[] COMPLEX_MANAGEMENT_KEY = new byte[]{
            0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };

    public final boolean isFipsApproved;
    public char[] defaultPin;
    public char[] defaultPuk;
    public byte[] defaultManagementKey;

    public static class Builder extends TestState.Builder<PivTestState.Builder> {

        public Builder(YubiKeyDevice device) {
            super(device);
        }

        public PivTestState build() throws Throwable {
            return new PivTestState(this);
        }
    }

    protected PivTestState(Builder builder) throws Throwable {
        super(builder);

        defaultPin = DEFAULT_PIN;
        defaultPuk = DEFAULT_PUK;
        defaultManagementKey = DEFAULT_MANAGEMENT_KEY;

        assumeTrue("No SmartCard support", currentDevice.supportsConnection(SmartCardConnection.class));

        DeviceInfo deviceInfo = getDeviceInfo();

        // skip MPE devices
        assumeFalse("Ignoring MPE device", isMpe(deviceInfo));

        boolean isPivFipsCapable = isFipsCapable(deviceInfo, Capability.PIV);
        boolean hasPinComplexity = deviceInfo != null && deviceInfo.getPinComplexity();

        if (scpParameters.getKid() == null && isPivFipsCapable) {
            assumeTrue("Trying to use PIV FIPS capable device over NFC without SCP", isUsbTransport());
        }

        if (scpParameters.getKid() != null) {
            // skip the test if the connected key does not provide matching SCP keys
            assumeTrue(
                    "No matching key params found for required kid",
                    scpParameters.getKeyParams() != null
            );
        }

        try (SmartCardConnection connection = openSmartCardConnection()) {
            PivSession pivSession = getPivSession(connection, scpParameters);
            assumeTrue("PIV not available", pivSession != null);

            try {
                pivSession.reset();
            } catch (Exception ignored) {
            }

            if (hasPinComplexity) {
                // only use complex pins if pin complexity is required
                pivSession.changePin(defaultPin, COMPLEX_PIN);
                pivSession.changePuk(defaultPuk, COMPLEX_PUK);
                pivSession.authenticate(defaultManagementKey);

                pivSession.setManagementKey(ManagementKeyType.AES192, COMPLEX_MANAGEMENT_KEY, false);

                defaultPin = COMPLEX_PIN;
                defaultPuk = COMPLEX_PUK;
                defaultManagementKey = COMPLEX_MANAGEMENT_KEY;
            }
        }

        deviceInfo = getDeviceInfo();
        isFipsApproved = isFipsApproved(deviceInfo, Capability.PIV);

        // after changing PIN, PUK and management key, we expect a FIPS capable device
        // to be FIPS approved
        if (isPivFipsCapable) {
            assertNotNull(deviceInfo);
            assertTrue("Device not PIV FIPS approved as expected", isFipsApproved);
        }
    }

    boolean isInvalidKeyType(KeyType keyType) {
        return isFipsApproved && (keyType == KeyType.RSA1024 || keyType == KeyType.X25519);
    }
}

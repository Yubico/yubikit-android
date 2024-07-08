/*
 * Copyright (C) 2020-2024 Yubico.
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

import static com.yubico.yubikit.piv.PivSession.FEATURE_AES_KEY;
import static com.yubico.yubikit.testing.piv.PivTestState.DEFAULT_MANAGEMENT_KEY;
import static com.yubico.yubikit.testing.piv.PivTestState.DEFAULT_PIN;
import static com.yubico.yubikit.testing.piv.PivTestState.DEFAULT_PUK;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.piv.InvalidPinException;
import com.yubico.yubikit.piv.ManagementKeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.testing.TestState;

import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.Assert;
import org.junit.Assume;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import javax.annotation.Nullable;

public class PivDeviceTests {

    private static final Logger logger = LoggerFactory.getLogger(PivDeviceTests.class);

    private static final char[] COMPLEX_PIN = "11234567".toCharArray();
    private static final char[] COMPLEX_PUK = "11234567".toCharArray();
    private static final byte[] COMPLEX_MANAGEMENT_KEY = new byte[]{
            0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };

    public static void testManagementKey(PivSession piv) throws BadResponseException, IOException, ApduException {
        byte[] key2 = Hex.decode("010203040102030401020304010203040102030401020304");

        ManagementKeyType managementKeyType = piv.getManagementKeyType();

        logger.debug("Authenticate with the wrong key");
        try {
            piv.authenticate(key2);
            Assert.fail("Authenticated with wrong key");
        } catch (ApduException e) {
            Assert.assertEquals(SW.SECURITY_CONDITION_NOT_SATISFIED, e.getSw());
        }

        logger.debug("Change management key");
        piv.authenticate(DEFAULT_MANAGEMENT_KEY);
        piv.setManagementKey(managementKeyType, key2, false);

        logger.debug("Authenticate with the old key");
        try {
            piv.authenticate(DEFAULT_MANAGEMENT_KEY);
            Assert.fail("Authenticated with wrong key");
        } catch (ApduException e) {
            Assert.assertEquals(SW.SECURITY_CONDITION_NOT_SATISFIED, e.getSw());
        }

        logger.debug("Change management key");
        piv.authenticate(key2);
        piv.setManagementKey(managementKeyType, DEFAULT_MANAGEMENT_KEY, false);
    }

    public static void testManagementKeyType(PivSession piv) throws BadResponseException, IOException, ApduException {
        Assume.assumeTrue("No AES key support", piv.supports(FEATURE_AES_KEY));

        ManagementKeyType managementKeyType = piv.getManagementKeyType();
        byte[] aes128Key = Hex.decode("01020304010203040102030401020304");

        logger.debug("Change management key type");
        piv.authenticate(DEFAULT_MANAGEMENT_KEY);
        piv.setManagementKey(ManagementKeyType.AES128, aes128Key, false);
        Assert.assertEquals(ManagementKeyType.AES128, piv.getManagementKeyType());

        try {
            piv.authenticate(DEFAULT_MANAGEMENT_KEY);
            Assert.fail("Authenticated with wrong key type");
        } catch (IllegalArgumentException e) {
            // ignored
        }

        // set original management key type
        piv.authenticate(aes128Key);
        piv.setManagementKey(managementKeyType, DEFAULT_MANAGEMENT_KEY, false);
    }

    public static void testPin(PivSession piv) throws ApduException, InvalidPinException, IOException, BadResponseException {
        // Ensure we only try this if the default management key is set.
        piv.authenticate(DEFAULT_MANAGEMENT_KEY);

        logger.debug("Verify PIN");
        char[] pin2 = "11231123".toCharArray();
        piv.verifyPin(DEFAULT_PIN);
        MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(3));

        logger.debug("Verify with wrong PIN");
        try {
            piv.verifyPin(pin2);
            Assert.fail("Verify with wrong PIN");
        } catch (InvalidPinException e) {
            MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(2));
            MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(2));
        }

        logger.debug("Change PIN with wrong PIN");
        try {
            piv.changePin(pin2, DEFAULT_PIN);
            Assert.fail("Change PIN with wrong PIN");
        } catch (InvalidPinException e) {
            MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(1));
            MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(1));
        }

        logger.debug("Change PIN");
        piv.changePin(DEFAULT_PIN, pin2);
        piv.verifyPin(pin2);

        logger.debug("Verify with wrong PIN");
        try {
            piv.verifyPin(DEFAULT_PIN);
            Assert.fail("Verify with wrong PIN");
        } catch (InvalidPinException e) {
            MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(2));
            MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(2));
        }

        logger.debug("Change PIN");
        piv.changePin(pin2, DEFAULT_PIN);
    }

    public static void testPuk(PivSession piv) throws ApduException, InvalidPinException, IOException, BadResponseException {
        // Ensure we only try this if the default management key is set.
        piv.authenticate(DEFAULT_MANAGEMENT_KEY);

        // Change PUK
        char[] puk2 = "12341234".toCharArray();
        piv.changePuk(DEFAULT_PUK, puk2);
        piv.verifyPin(DEFAULT_PIN);

        // Block PIN
        while (piv.getPinAttempts() > 0) {
            try {
                piv.verifyPin(puk2);
            } catch (InvalidPinException e) {
                //Re-run until blocked...
            }
        }

        // Verify PIN blocked
        try {
            piv.verifyPin(DEFAULT_PIN);
        } catch (InvalidPinException e) {
            MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(0));
            MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(0));
        }

        // Try unblock with wrong PUK
        try {
            piv.unblockPin(DEFAULT_PUK, DEFAULT_PIN);
            Assert.fail("Unblock with wrong PUK");
        } catch (InvalidPinException e) {
            MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(2));
        }

        // Unblock PIN
        piv.unblockPin(puk2, DEFAULT_PIN);

        // Try to change PUK with wrong PUK
        try {
            piv.changePuk(DEFAULT_PUK, puk2);
            Assert.fail("Change PUK with wrong PUK");
        } catch (InvalidPinException e) {
            MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(2));
        }

        // Change PUK
        piv.changePuk(puk2, DEFAULT_PUK);
    }

    public static void verifyAndSetup(YubiKeyDevice device, @Nullable Byte kid) throws Throwable {

        PivTestState.DEFAULT_PIN = PivTestConstants.DEFAULT_PIN;
        PivTestState.DEFAULT_PUK = PivTestConstants.DEFAULT_PUK;
        PivTestState.DEFAULT_MANAGEMENT_KEY = PivTestConstants.DEFAULT_MANAGEMENT_KEY;

        boolean isPivFipsCapable;
        boolean hasPinComplexity;

        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            ManagementSession managementSession = new ManagementSession(connection);
            DeviceInfo deviceInfo = managementSession.getDeviceInfo();
            assertNotNull(deviceInfo);

            isPivFipsCapable = (deviceInfo.getFipsCapable() & Capability.PIV.bit) == Capability.PIV.bit;
            hasPinComplexity = deviceInfo.getPinComplexity();
        }

        if (kid != null) {
            assumeTrue("Device is not PIV FIPS capable", isPivFipsCapable);
        } else if (isPivFipsCapable) {
            Assume.assumeTrue("Trying to use PIV FIPS capable device over NFC without SCP",
                    device.getTransport() != Transport.NFC);
        }

        // don't read SCP params on non capable devices
        TestState.keyParams = (isPivFipsCapable && kid != null)
                ? TestState.readScpKeyParams(device, kid)
                : null;

        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            PivSession pivSession = new PivSession(connection, TestState.keyParams);
            pivSession.reset();

            if (hasPinComplexity) {
                // only use complex pins if pin complexity is required
                pivSession.changePin(DEFAULT_PIN, COMPLEX_PIN);
                pivSession.changePuk(DEFAULT_PUK, COMPLEX_PUK);
                pivSession.authenticate(DEFAULT_MANAGEMENT_KEY);

                pivSession.setManagementKey(ManagementKeyType.AES192, COMPLEX_MANAGEMENT_KEY, false);

                PivTestState.DEFAULT_PIN = COMPLEX_PIN;
                PivTestState.DEFAULT_PUK = COMPLEX_PUK;
                PivTestState.DEFAULT_MANAGEMENT_KEY = COMPLEX_MANAGEMENT_KEY;
            }

            if (kid == null && device.getTransport() == Transport.USB) {
                // this might be a FIPS capable (and now approved) device,
                // but the test client did not provide any kid, so the session is not
                // in SCP mode and we don't require this test to run in SCP for USB transports.
                // FIPS devices have to use SCP over NFC transport
                return;
            }

            ManagementSession managementSession = new ManagementSession(connection);
            DeviceInfo deviceInfo = managementSession.getDeviceInfo();

            final boolean fipsApproved = (deviceInfo.getFipsApproved() & Capability.PIV.bit) == Capability.PIV.bit;

            assertNotNull(deviceInfo);
            assertTrue("Device not PIV FIPS approved", fipsApproved);
        }
    }
}

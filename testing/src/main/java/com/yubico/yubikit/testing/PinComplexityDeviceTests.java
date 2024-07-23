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

import static com.yubico.yubikit.core.fido.CtapException.ERR_PIN_POLICY_VIOLATION;
import static com.yubico.yubikit.core.smartcard.SW.CONDITIONS_NOT_SATISFIED;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.openpgp.OpenPgpSession;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.openpgp.OpenPgpTestState;
import com.yubico.yubikit.testing.piv.PivTestState;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.Assert;

import java.util.Objects;

public class PinComplexityDeviceTests {

    private static void verifyDevice(TestState state) {
        final DeviceInfo deviceInfo = state.getDeviceInfo();
        assumeTrue("Device does not support PIN complexity", deviceInfo != null);
        assumeTrue("Device does not require PIN complexity", deviceInfo.getPinComplexity());
    }

    /**
     * For this test, one needs a key with PIN complexity set on. The test will change PINs.
     * <p>
     * The test will verify that trying to set a weak PIN for PIV produces expected exceptions.
     *
     * @see DeviceInfo#getPinComplexity()
     */
    public static void testPivPinComplexity(PivSession piv, PivTestState state) throws Throwable {

        verifyDevice(state);

        piv.reset();
        piv.authenticate(state.defaultManagementKey);

        piv.verifyPin(state.defaultPin);

        MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(3));

        // try to change to pin which breaks PIN complexity
        char[] weakPin = "33333333".toCharArray();
        try {
            piv.changePin(state.defaultPin, weakPin);
            Assert.fail("Set weak PIN");
        } catch (ApduException apduException) {
            if (apduException.getSw() != CONDITIONS_NOT_SATISFIED) {
                Assert.fail("Unexpected exception:" + apduException.getMessage());
            }
        } catch (Exception e) {
            Assert.fail("Unexpected exception:" + e.getMessage());
        }

        piv.verifyPin(state.defaultPin);

        // change to complex pin
        char[] complexPin = "CMPLXPIN".toCharArray();
        try {
            piv.changePin(state.defaultPin, complexPin);
        } catch (Exception e) {
            Assert.fail("Unexpected exception:" + e.getMessage());
        }

        piv.verifyPin(complexPin);

        piv.changePin(complexPin, state.defaultPin);
    }


    /**
     * For this test, one needs a key with PIN complexity set on. The test will change PINs.
     * <p>
     * The test will verify that trying to set a weak user PIN for OpenPgp produces expected exceptions.
     *
     * @see DeviceInfo#getPinComplexity()
     */
    public static void testOpenPgpPinComplexity(OpenPgpSession openpgp, OpenPgpTestState state) throws Throwable {

        verifyDevice(state);

        openpgp.reset();
        openpgp.verifyUserPin(state.defaultUserPin, false);

        char[] weakPin = "33333333".toCharArray();
        try {
            openpgp.changeUserPin(state.defaultUserPin, weakPin);
        } catch (ApduException apduException) {
            if (apduException.getSw() != CONDITIONS_NOT_SATISFIED) {
                fail("Unexpected exception");
            }
        } catch (Exception e) {
            fail("Unexpected exception");
        }

        // set complex pin
        char[] complexPin = "CMPLXPIN".toCharArray();
        try {
            openpgp.changeUserPin(state.defaultUserPin, complexPin);
        } catch (Exception e) {
            Assert.fail("Unexpected exception");
        }

        openpgp.changeUserPin(complexPin, state.defaultUserPin);
    }

    public static void testFido2PinComplexity(FidoTestState state) throws Throwable {

        verifyDevice(state);

        state.withCtap2(ctap2 -> {
            PinUvAuthProtocol pinUvAuthProtocol = new PinUvAuthProtocolV2();
            char[] defaultPin = "11234567".toCharArray();

            Ctap2Session.InfoData info = ctap2.getCachedInfo();
            ClientPin pin = new ClientPin(ctap2, pinUvAuthProtocol);
            boolean pinSet = Objects.requireNonNull((Boolean) info.getOptions().get("clientPin"));

            try {
                if (!pinSet) {
                    pin.setPin(defaultPin);
                } else {
                    pin.getPinToken(
                            defaultPin,
                            ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA,
                            "localhost");
                }
            } catch (ApduException e) {
                fail("Failed to set or use PIN. Reset the device and try again");
            }

            assertThat(pin.getPinUvAuth().getVersion(), is(pinUvAuthProtocol.getVersion()));
            assertThat(pin.getPinRetries().getCount(), is(8));

            char[] weakPin = "33333333".toCharArray();
            try {
                pin.changePin(defaultPin, weakPin);
                fail("Weak PIN was accepted");
            } catch (CtapException e) {
                assertThat(e.getCtapError(), is(ERR_PIN_POLICY_VIOLATION));
            }

            char[] strongPin = "STRONG PIN".toCharArray();
            pin.changePin(defaultPin, strongPin);
            pin.changePin(strongPin, defaultPin);

            assertThat(pin.getPinRetries().getCount(), is(8));
        });
    }
}

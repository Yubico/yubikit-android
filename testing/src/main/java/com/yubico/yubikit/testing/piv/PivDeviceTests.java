/*
 * Copyright (C) 2020-2022 Yubico.
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

import static com.yubico.yubikit.testing.piv.PivTestConstants.DEFAULT_MANAGEMENT_KEY;
import static com.yubico.yubikit.testing.piv.PivTestConstants.DEFAULT_PIN;
import static com.yubico.yubikit.testing.piv.PivTestConstants.DEFAULT_PUK;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.piv.InvalidPinException;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.ManagementKeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;
import com.yubico.yubikit.piv.jca.PivAlgorithmParameterSpec;

import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.Assert;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;

public class PivDeviceTests {

    public static void testManagementKey(PivSession piv) throws BadResponseException, IOException, ApduException {
        byte[] key2 = Hex.decode("010203040102030401020304010203040102030401020304");

        Logger.d("Authenticate with the wrong key");
        try {
            piv.authenticate(ManagementKeyType.TDES, key2);
            Assert.fail("Authenticated with wrong key");
        } catch (ApduException e) {
            Assert.assertEquals(SW.SECURITY_CONDITION_NOT_SATISFIED, e.getSw());
        }

        Logger.d("Change management key");
        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);
        piv.setManagementKey(ManagementKeyType.TDES, key2, false);

        Logger.d("Authenticate with the old key");
        try {
            piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);
            Assert.fail("Authenticated with wrong key");
        } catch (ApduException e) {
            Assert.assertEquals(SW.SECURITY_CONDITION_NOT_SATISFIED, e.getSw());
        }

        Logger.d("Change management key");
        piv.authenticate(ManagementKeyType.TDES, key2);
        piv.setManagementKey(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY, false);
    }

    public static void testPin(PivSession piv) throws ApduException, InvalidPinException, IOException, BadResponseException {
        // Ensure we only try this if the default management key is set.
        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);

        Logger.d("Verify PIN");
        char[] pin2 = "123123".toCharArray();
        piv.verifyPin(DEFAULT_PIN);
        MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(3));

        Logger.d("Verify with wrong PIN");
        try {
            piv.verifyPin(pin2);
            Assert.fail("Verify with wrong PIN");
        } catch (InvalidPinException e) {
            MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(2));
            MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(2));
        }

        Logger.d("Change PIN with wrong PIN");
        try {
            piv.changePin(pin2, DEFAULT_PIN);
            Assert.fail("Change PIN with wrong PIN");
        } catch (InvalidPinException e) {
            MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(1));
            MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(1));
        }

        Logger.d("Change PIN");
        piv.changePin(DEFAULT_PIN, pin2);
        piv.verifyPin(pin2);

        Logger.d("Verify with wrong PIN");
        try {
            piv.verifyPin(DEFAULT_PIN);
            Assert.fail("Verify with wrong PIN");
        } catch (InvalidPinException e) {
            MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(2));
            MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(2));
        }

        Logger.d("Change PIN");
        piv.changePin(pin2, DEFAULT_PIN);
    }

    public static void testPuk(PivSession piv) throws ApduException, InvalidPinException, IOException, BadResponseException {
        // Ensure we only try this if the default management key is set.
        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);

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

    public static void testEcdh(PivSession piv, KeyType keyType) throws BadResponseException, IOException, ApduException, NoSuchAlgorithmException, InvalidKeyException, InvalidPinException {
        if (keyType.params.algorithm != KeyType.Algorithm.EC) {
            throw new IllegalArgumentException("Unsupported");
        }

        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);
        PublicKey publicKey = piv.generateKey(Slot.AUTHENTICATION, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);
        KeyPair peer = PivTestUtils.generateKey(keyType);

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(peer.getPrivate());
        ka.doPhase(publicKey, true);
        byte[] expected = ka.generateSecret();

        piv.verifyPin(DEFAULT_PIN);
        byte[] secret = piv.calculateSecret(Slot.AUTHENTICATION, (ECPublicKey) peer.getPublic());

        Assert.assertArrayEquals(expected, secret);
    }
}

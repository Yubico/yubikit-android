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

import static com.yubico.yubikit.core.smartcard.SW.REFERENCED_DATA_NOT_FOUND;
import static com.yubico.yubikit.piv.KeyType.Algorithm.EC;
import static com.yubico.yubikit.piv.PivSession.FEATURE_MOVE_KEY;
import static com.yubico.yubikit.testing.piv.PivJcaSigningTests.testSign;
import static com.yubico.yubikit.testing.piv.PivJcaUtils.setupJca;
import static com.yubico.yubikit.testing.piv.PivJcaUtils.tearDownJca;
import static com.yubico.yubikit.testing.piv.PivTestConstants.DEFAULT_MANAGEMENT_KEY;
import static com.yubico.yubikit.testing.piv.PivTestConstants.DEFAULT_PIN;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.ManagementKeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;

import org.junit.Assert;
import org.junit.Assume;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class PivMoveKeyTests {

    static void moveKey(PivSession piv)
            throws IOException, ApduException, BadResponseException, NoSuchAlgorithmException {
        Assume.assumeTrue("Skipped because the key does not support this feature", piv.supports(FEATURE_MOVE_KEY));

        setupJca(piv);
        Slot srcSlot = Slot.RETIRED1;
        Slot dstSlot = Slot.RETIRED2;

        piv.authenticate(PivTestUtils.getManagementKeyType(piv), DEFAULT_MANAGEMENT_KEY);

        for (KeyType keyType : Arrays.asList(KeyType.ECCP256, KeyType.ECCP384, KeyType.RSA1024, KeyType.RSA2048, KeyType.RSA3072, KeyType.RSA4096)) {

            KeyPair keyPair = PivTestUtils.loadKey(keyType);
            PrivateKeyValues privateKeyValues = PrivateKeyValues.fromPrivateKey(keyPair.getPrivate());
            piv.putKey(srcSlot, privateKeyValues, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);

            if (hasKey(piv, dstSlot)) {
                piv.deleteKey(dstSlot);
            }

            piv.moveKey(srcSlot, dstSlot);
            Assert.assertFalse("Key in srcSlot still exists", hasKey(piv, srcSlot));

            try {
                KeyStore keyStore = KeyStore.getInstance("YKPiv");
                keyStore.load(null);

                PublicKey publicKey = keyPair.getPublic();
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(dstSlot.getStringAlias(), DEFAULT_PIN);
                KeyPair signingKeyPair = new KeyPair(publicKey, privateKey);

                testSign(signingKeyPair, keyType.params.algorithm == EC
                        ? "SHA256withECDSA"
                        : "SHA256withRSA", null);

            } catch (KeyStoreException | UnrecoverableKeyException |
                     InvalidAlgorithmParameterException | InvalidKeyException |
                     SignatureException | CertificateException e) {
                throw new RuntimeException(e);
            }

        }
        tearDownJca();
    }

    private static boolean hasKey(PivSession piv, Slot slot) throws IOException, ApduException {
        try {
            piv.getSlotMetadata(slot);
        } catch (ApduException apduException) {
            if (apduException.getSw() == REFERENCED_DATA_NOT_FOUND) {
                return false;
            }
            throw apduException;
        }
        return true;
    }
}

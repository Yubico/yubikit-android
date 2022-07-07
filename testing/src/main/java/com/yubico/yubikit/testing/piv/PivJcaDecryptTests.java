/*
 * Copyright (C) 2022 Yubico.
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

import static com.yubico.yubikit.testing.piv.PivJcaUtils.setupJca;
import static com.yubico.yubikit.testing.piv.PivJcaUtils.tearDownJca;
import static com.yubico.yubikit.testing.piv.PivTestConstants.DEFAULT_MANAGEMENT_KEY;
import static com.yubico.yubikit.testing.piv.PivTestConstants.DEFAULT_PIN;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.ManagementKeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;
import com.yubico.yubikit.piv.jca.PivAlgorithmParameterSpec;

import org.junit.Assert;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class PivJcaDecryptTests {

    public static void testDecrypt(PivSession piv) throws BadResponseException, IOException, ApduException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        setupJca(piv);
        for (KeyType keyType : KeyType.values()) {
            if (keyType.params.algorithm.name().equals("RSA")) {
                testDecrypt(piv, keyType);
            }
        }
        tearDownJca();
    }

    public static void testDecrypt(PivSession piv, KeyType keyType) throws BadResponseException, IOException, ApduException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        if (keyType.params.algorithm != KeyType.Algorithm.RSA) {
            throw new IllegalArgumentException("Unsupported");
        }

        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);
        Logger.d("Generate key: " + keyType);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("YKPivRSA");
        kpg.initialize(new PivAlgorithmParameterSpec(Slot.KEY_MANAGEMENT, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT, DEFAULT_PIN));
        KeyPair pair = kpg.generateKeyPair();

        testDecrypt(pair, Cipher.getInstance("RSA/ECB/PKCS1Padding"));
        testDecrypt(pair, Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"));
        testDecrypt(pair, Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));
    }

    public static void testDecrypt(KeyPair keyPair, Cipher cipher) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] message = "Hello world!".getBytes(StandardCharsets.UTF_8);

        Logger.d("Using cipher " + cipher.getAlgorithm());

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] ct = cipher.doFinal(message);
        Logger.d("Cipher text " + ct.length + ": " + StringUtils.bytesToHex(ct));

        Cipher decryptCipher = Cipher.getInstance(cipher.getAlgorithm());
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] pt = decryptCipher.doFinal(ct);

        Assert.assertArrayEquals(message, pt);
        Logger.d("Decrypt successful for " + cipher.getAlgorithm());
    }
}

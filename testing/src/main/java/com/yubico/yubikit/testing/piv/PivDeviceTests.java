/*
 * Copyright (C) 2020 Yubico.
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
import com.yubico.yubikit.piv.jca.PivPrivateKey;
import com.yubico.yubikit.piv.jca.PivProvider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;

public class PivDeviceTests {
    private static final byte[] DEFAULT_MANAGEMENT_KEY = Hex.decode("010203040506070801020304050607080102030405060708");
    private static final char[] DEFAULT_PIN = "123456".toCharArray();
    private static final char[] DEFAULT_PUK = "12345678".toCharArray();

    private static final List<String> MESSAGE_DIGESTS = Arrays.asList("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512");

    /*
    public static void initProviders() {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new PivProvider());
    }
     */

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

    public static void testSignAllHashes(PivSession piv, Slot slot, KeyType keyType, PublicKey publicKey) throws ApduException, NoSuchAlgorithmException, InvalidPinException, IOException, InvalidKeyException, BadResponseException {
        for (String hash : MESSAGE_DIGESTS) {
            testSign(piv, slot, keyType, publicKey, hash);
        }
    }

    public static void testSign(PivSession piv, Slot slot, KeyType keyType, PublicKey publicKey, String digest) throws NoSuchAlgorithmException, IOException, ApduException, InvalidPinException, InvalidKeyException, BadResponseException {
        byte[] message = "Hello world!".getBytes(StandardCharsets.UTF_8);

        String signatureAlgorithm = digest.replace("-", "") + "with";
        switch (keyType.params.algorithm) {
            case RSA:
                signatureAlgorithm += "RSA";
                break;
            case EC:
                signatureAlgorithm += "ECDSA";
                break;
        }

        Logger.d("Create signature");
        //byte[] signature = piv.sign(slot, keyType, message, sig);
        try {
            Signature sig = Signature.getInstance(signatureAlgorithm);

            KeyStore keyStore = KeyStore.getInstance("YKPiv");
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(Integer.toString(slot.value, 16), DEFAULT_PIN);
            sig.initSign(privateKey);
            sig.update(message);
            byte[] signature = sig.sign();

            // Verify
            sig = Signature.getInstance(signatureAlgorithm);
            sig.initVerify(publicKey);
            sig.update(message);
            Assert.assertTrue("Verify signature", sig.verify(signature));
        } catch (InvalidKeyException | SignatureException | KeyStoreException | CertificateException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static void testSign(PivSession piv, KeyType keyType) throws NoSuchAlgorithmException, IOException, ApduException, InvalidPinException, InvalidKeyException, BadResponseException, InvalidAlgorithmParameterException, SignatureException {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new PivProvider(piv));
        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);
        Logger.d("Generate key: " + keyType);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyType.params.algorithm.name());
        kpg.initialize(new PivAlgorithmParameterSpec(Slot.SIGNATURE, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT, DEFAULT_PIN));
        KeyPair keyPair = kpg.generateKeyPair();

        //PublicKey publicKey = piv.generateKey(Slot.SIGNATURE, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);
        //PrivateKey privateKey = PivPrivateKey.from(publicKey, Slot.SIGNATURE, DEFAULT_PIN);

        switch (keyType.params.algorithm) {
            case EC:
                testSign(keyPair, "SHA1withECDSA", null);
                testSign(keyPair, "SHA256withECDSA", null);
                testSign(keyPair, "NONEwithECDSA", null);
                testSign(keyPair, "SHA3-256withECDSA", null);
                break;
            case RSA:
                testSign(keyPair, "SHA1withRSA", null);
                testSign(keyPair, "SHA256withRSA", null);
                testSign(keyPair, "RSASSA-PSS", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 8, 1));

                // Test with custom parameter. We use a 0-length salt and ensure signatures are the same
                PSSParameterSpec param = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 0, 1);
                byte[] sig1 = testSign(keyPair, "RSASSA-PSS", param);
                byte[] sig2 = testSign(keyPair, "RSASSA-PSS", param);
                Assert.assertArrayEquals("PSS parameters not used, signatures are not identical!", sig1, sig2);
                break;
        }
    }

    public static byte[] testSign(KeyPair keyPair, String signatureAlgorithm, AlgorithmParameterSpec param) throws NoSuchAlgorithmException, IOException, ApduException, InvalidPinException, BadResponseException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        byte[] message = "Hello world!".getBytes(StandardCharsets.UTF_8);

        Logger.d("Create signature using " + signatureAlgorithm);
        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(keyPair.getPrivate());
        if (param != null) signer.setParameter(param);
        signer.update(message);
        byte[] signature = signer.sign();

        //byte[] signature = piv.sign(Slot.SIGNATURE, KeyType.fromKey(publicKey), message, signatureAlgorithm);
        try {
            Signature verifier = Signature.getInstance(signatureAlgorithm);
            verifier.initVerify(keyPair.getPublic());
            if (param != null) verifier.setParameter(param);
            verifier.update(message);
            Assert.assertTrue("Verify signature", verifier.verify(signature));
            Logger.d("Signature verified for: " + signatureAlgorithm);
            return signature;
        } catch (InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public static void testDecrypt(PivSession piv, KeyType keyType) throws BadResponseException, IOException, ApduException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidPinException, InvalidAlgorithmParameterException {
        if (keyType.params.algorithm != KeyType.Algorithm.RSA) {
            throw new IllegalArgumentException("Unsupported");
        }

        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);
        Logger.d("Generate key: " + keyType);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyType.params.algorithm.name());
        kpg.initialize(new PivAlgorithmParameterSpec(Slot.KEY_MANAGEMENT, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT, DEFAULT_PIN));
        KeyPair pair = kpg.generateKeyPair();

        testDecrypt(pair, Cipher.getInstance("RSA/ECB/PKCS1Padding"));
        testDecrypt(pair, Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"));
        testDecrypt(pair, Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));
    }

    public static void testDecrypt(KeyPair keyPair, Cipher cipher) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidPinException {
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

    public static void testImportKeys(PivSession piv) throws ApduException, BadResponseException, NoSuchAlgorithmException, IOException, InvalidPinException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, SignatureException {
        for (KeyType keyType : KeyType.values()) {
            testImportKey(piv, PivTestUtils.loadKey(keyType));
            testImportKey(piv, PivTestUtils.generateKey(keyType));
        }
    }

    public static void testImportKey(PivSession piv, KeyPair keyPair) throws BadResponseException, IOException, ApduException, NoSuchAlgorithmException, InvalidPinException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Slot slot = Slot.AUTHENTICATION;
        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);

        Logger.d("Import key in slot " + slot);
        KeyType keyType = piv.putKey(slot, keyPair.getPrivate(), PinPolicy.DEFAULT, TouchPolicy.DEFAULT);

        testSignAllHashes(piv, slot, keyType, keyPair.getPublic());
    }

    public static void testGenerateKeys(PivSession piv) throws BadResponseException, IOException, ApduException, InvalidPinException, NoSuchAlgorithmException, InvalidKeyException {
        for (KeyType keyType : KeyType.values()) {
            testGenerateKey(piv, keyType);
        }
    }

    public static void testGenerateKey(PivSession piv, KeyType keyType) throws BadResponseException, IOException, ApduException, InvalidPinException, NoSuchAlgorithmException, InvalidKeyException {
        Slot slot = Slot.AUTHENTICATION;
        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);

        Logger.d("Generate an " + keyType + " key in slot " + slot);
        PublicKey pub = piv.generateKey(slot, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);

        testSignAllHashes(piv, slot, keyType, pub);
    }

    public static void testProviderWithDevice(PivSession piv) throws Exception {
        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);
        piv.verifyPin(DEFAULT_PIN);

        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        for (KeyType keyType : Arrays.asList(KeyType.ECCP256, KeyType.ECCP384)) {
        ecGen.initialize(new PivAlgorithmParameterSpec(Slot.AUTHENTICATION, keyType, null, null, null));
            KeyPair keyPair = ecGen.generateKeyPair();
            PivTestUtils.ecSignAndVerify(keyPair.getPrivate(), keyPair.getPublic());
            PivTestUtils.ecKeyAgreement(keyPair.getPrivate(), keyPair.getPublic());
        }

        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        for (KeyType keyType : Arrays.asList(KeyType.RSA1024, KeyType.RSA2048)) {
            rsaGen.initialize(new PivAlgorithmParameterSpec(Slot.AUTHENTICATION, keyType, null, null, null));
            KeyPair keyPair = rsaGen.generateKeyPair();
            PivTestUtils.rsaEncryptAndDecrypt(keyPair.getPrivate(), keyPair.getPublic());
            PivTestUtils.rsaSignAndVerify(keyPair.getPrivate(), keyPair.getPublic());
        }
    }
}

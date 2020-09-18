package com.yubico.yubikit.testing.piv;

import com.yubico.yubikit.core.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.InvalidPinException;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivApplication;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;
import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.StringUtils;

import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.Assert;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
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

    public static void testManagementKey(PivApplication piv) throws BadResponseException, IOException, ApduException {
        byte[] key2 = Hex.decode("010203040102030401020304010203040102030401020304");

        Logger.d("Authenticate with the wrong key");
        try {
            piv.authenticate(key2);
            Assert.fail("Authenticated with wrong key");
        } catch (ApduException e) {
            Assert.assertEquals(0x6982, e.getStatusCode());
        }

        Logger.d("Change management key");
        piv.authenticate(DEFAULT_MANAGEMENT_KEY);
        piv.setManagementKey(key2);

        Logger.d("Authenticate with the old key");
        try {
            piv.authenticate(DEFAULT_MANAGEMENT_KEY);
            Assert.fail("Authenticated with wrong key");
        } catch (ApduException e) {
            Assert.assertEquals(0x6982, e.getStatusCode());
        }

        Logger.d("Change management key");
        piv.authenticate(key2);
        piv.setManagementKey(DEFAULT_MANAGEMENT_KEY);
    }

    public static void testPin(PivApplication piv) throws ApduException, InvalidPinException, IOException, BadResponseException {
        // Ensure we only try this if the default management key is set.
        piv.authenticate(DEFAULT_MANAGEMENT_KEY);

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

    public static void testPuk(PivApplication piv) throws ApduException, InvalidPinException, IOException, BadResponseException {
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

    public static void testSignAllHashes(PivApplication piv, Slot slot, KeyType keyType, PublicKey publicKey) throws ApduException, NoSuchAlgorithmException, InvalidPinException, IOException, InvalidKeyException, BadResponseException {
        for (String hash : MESSAGE_DIGESTS) {
            testSign(piv, slot, keyType, publicKey, hash);
        }
    }

    public static void testSign(PivApplication piv, Slot slot, KeyType keyType, PublicKey publicKey, String digest) throws NoSuchAlgorithmException, IOException, ApduException, InvalidPinException, InvalidKeyException, BadResponseException {
        byte[] message = "Hello world!".getBytes(StandardCharsets.UTF_8);

        String signatureAlgorithm = digest.replace("-", "") + "With";
        switch (keyType.params.algorithm) {
            case RSA:
                signatureAlgorithm += "RSA";
                break;
            case EC:
                signatureAlgorithm += "ECDSA";
                break;
        }

        Logger.d("Create signature");
        piv.verifyPin(DEFAULT_PIN);
        byte[] signature = piv.sign(slot, keyType, message, signatureAlgorithm);
        Signature sig = Signature.getInstance(signatureAlgorithm);
        try {
            sig.initVerify(publicKey);
            sig.update(message);
            Assert.assertTrue("Verify signature", sig.verify(signature));
        } catch (InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public static void testDecrypt(PivApplication piv, KeyType keyType) throws BadResponseException, IOException, ApduException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidPinException {
        if (keyType.params.algorithm != KeyType.Algorithm.RSA) {
            throw new IllegalArgumentException("Unsupported");
        }

        byte[] message = "Hello world!".getBytes(StandardCharsets.UTF_8);

        piv.authenticate(DEFAULT_MANAGEMENT_KEY);
        PublicKey publicKey = piv.generateKey(Slot.AUTHENTICATION, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);

        String algorithm = "RSA/ECB/PKCS1Padding";
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ct = cipher.doFinal(message);
        Logger.d("Cipher text " + ct.length + ": " + StringUtils.bytesToHex(ct));

        piv.verifyPin(DEFAULT_PIN);
        byte[] pt = piv.decrypt(Slot.AUTHENTICATION, ct, algorithm);

        Assert.assertArrayEquals(message, pt);
    }

    public static void testEcdh(PivApplication piv, KeyType keyType) throws BadResponseException, IOException, ApduException, NoSuchAlgorithmException, InvalidKeyException, InvalidPinException {
        if (keyType.params.algorithm != KeyType.Algorithm.EC) {
            throw new IllegalArgumentException("Unsupported");
        }

        piv.authenticate(DEFAULT_MANAGEMENT_KEY);
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

    public static void testImportKeys(PivApplication piv) throws ApduException, BadResponseException, NoSuchAlgorithmException, IOException, InvalidPinException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, SignatureException {
        for (KeyType keyType : KeyType.values()) {
            testImportKey(piv, PivTestUtils.loadKey(keyType));
            testImportKey(piv, PivTestUtils.generateKey(keyType));
        }
    }

    public static void testImportKey(PivApplication piv, KeyPair keyPair) throws BadResponseException, IOException, ApduException, NoSuchAlgorithmException, InvalidPinException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Slot slot = Slot.AUTHENTICATION;
        piv.authenticate(DEFAULT_MANAGEMENT_KEY);

        Logger.d("Import key in slot " + slot);
        KeyType keyType = piv.putKey(slot, keyPair.getPrivate(), PinPolicy.DEFAULT, TouchPolicy.DEFAULT);

        testSignAllHashes(piv, slot, keyType, keyPair.getPublic());
    }

    public static void testGenerateKeys(PivApplication piv) throws BadResponseException, IOException, ApduException, InvalidPinException, NoSuchAlgorithmException, InvalidKeyException {
        for (KeyType keyType : KeyType.values()) {
            testGenerateKey(piv, keyType);
        }
    }

    public static void testGenerateKey(PivApplication piv, KeyType keyType) throws BadResponseException, IOException, ApduException, InvalidPinException, NoSuchAlgorithmException, InvalidKeyException {
        Slot slot = Slot.AUTHENTICATION;
        piv.authenticate(DEFAULT_MANAGEMENT_KEY);

        Logger.d("Generate an " + keyType + " key in slot " + slot);
        PublicKey pub = piv.generateKey(slot, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);

        testSignAllHashes(piv, slot, keyType, pub);
    }
}

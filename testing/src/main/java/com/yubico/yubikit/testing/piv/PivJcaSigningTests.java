package com.yubico.yubikit.testing.piv;

import static com.yubico.yubikit.testing.piv.PivJcaUtils.setupJca;
import static com.yubico.yubikit.testing.piv.PivJcaUtils.tearDownJca;
import static com.yubico.yubikit.testing.piv.PivTestConstants.DEFAULT_MANAGEMENT_KEY;
import static com.yubico.yubikit.testing.piv.PivTestConstants.DEFAULT_PIN;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
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
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class PivJcaSigningTests {

    public static void testSign(PivSession piv) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, ApduException, InvalidKeyException, BadResponseException, InvalidAlgorithmParameterException, SignatureException {
        setupJca(piv);
        for (KeyType keyType : KeyType.values()) {
            testSign(piv, keyType);
        }
        tearDownJca();
    }

    public static void testSign(PivSession piv, KeyType keyType) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, ApduException, InvalidKeyException, BadResponseException, InvalidAlgorithmParameterException, SignatureException {
        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);
        Logger.d("Generate key: " + keyType);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyType.params.algorithm.name(), "YKPiv");
        kpg.initialize(new PivAlgorithmParameterSpec(Slot.SIGNATURE, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT, DEFAULT_PIN));
        KeyPair keyPair = kpg.generateKeyPair();

        switch (keyType.params.algorithm) {
            case EC:
                testSign(keyPair, "SHA1withECDSA", null);
                testSign(keyPair, "SHA256withECDSA", null);
                //noinspection SpellCheckingInspection
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

    public static byte[] testSign(KeyPair keyPair, String signatureAlgorithm, AlgorithmParameterSpec param) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        byte[] message = "Hello world!".getBytes(StandardCharsets.UTF_8);

        Logger.d("Create signature using " + signatureAlgorithm);
        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(keyPair.getPrivate());
        if (param != null) signer.setParameter(param);
        signer.update(message);
        byte[] signature = signer.sign();

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

    /* TODO review following
    private static final List<String> MESSAGE_DIGESTS = Arrays.asList("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512");

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
        try {
            Signature sig = Signature.getInstance(signatureAlgorithm);

            KeyStore keyStore = KeyStore.getInstance("YKPiv");
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(slot.getStringAlias(), DEFAULT_PIN);
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
*/
}

/*
 * Copyright (C) 2023 Yubico.
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

package com.yubico.yubikit.testing.openpgp;

import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.openpgp.KeyRef;
import com.yubico.yubikit.openpgp.OpenPgpAid;
import com.yubico.yubikit.openpgp.OpenPgpCurve;
import com.yubico.yubikit.openpgp.OpenPgpSession;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.KeyAgreement;

public class OpenPgpDeviceTests {
    private static final Logger logger = LoggerFactory.getLogger(OpenPgpDeviceTests.class);

    public static void testGenerateRsaKeys(OpenPgpSession openpgp) throws Exception {
        openpgp.verifyAdminPin("12345678");

        for (int keySize: Arrays.asList(2048, 4096)) {
            openpgp.generateRsaKey(KeyRef.SIG, keySize).toPublicKey();
            //TODO: Test signing, verifying
        }
    }

    public static void testGenerateEcKeys(OpenPgpSession openpgp) throws Exception {
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        openpgp.verifyAdminPin("12345678");

        for (OpenPgpCurve curve: OpenPgpCurve.values()) {
            openpgp.generateEcKey(curve == OpenPgpCurve.X25519 ? KeyRef.DEC : KeyRef.SIG, curve);
            //TODO: Test signing, verifying
        }
    }

    public static void testImportRsaKeys(OpenPgpSession openpgp) throws Exception {
        openpgp.verifyAdminPin("12345678");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        byte[] message = "hello".getBytes(StandardCharsets.UTF_8);
        for (int keySize: Arrays.asList(2048, 4096)) {
            kpg.initialize(keySize);
            KeyPair pair = kpg.generateKeyPair();
            openpgp.putKey(KeyRef.SIG, PrivateKeyValues.fromPrivateKey(pair.getPrivate()));

            Assert.assertArrayEquals(pair.getPublic().getEncoded(), openpgp.getPublicKey(KeyRef.SIG).getEncoded());

            PublicKey publicKey = openpgp.getPublicKey(KeyRef.SIG).toPublicKey();
            openpgp.verifyUserPin("123456", false);
            byte[] signature = openpgp.sign(message);
            System.out.println("Signature: " + Hex.toHexString(signature));

            Signature verifier = Signature.getInstance("NONEwithRSA");
            verifier.initVerify(publicKey);
            verifier.update(message);
            assert verifier.verify(signature);
        }
    }

    public static void testImportEcDsaKeys(OpenPgpSession openpgp) throws Exception {
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        openpgp.verifyAdminPin("12345678");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA");
        List<OpenPgpCurve> curves = new ArrayList<>(Arrays.asList(OpenPgpCurve.values()));
        curves.remove(OpenPgpCurve.Ed25519);
        curves.remove(OpenPgpCurve.X25519);


        byte[] message = "hello".getBytes(StandardCharsets.UTF_8);
        for (OpenPgpCurve curve : curves) {
            kpg.initialize(new ECGenParameterSpec(curve.name()));
            KeyPair pair = kpg.generateKeyPair();
            System.out.println("Curve: " + curve);
            System.out.println("Encoded private key: " + Hex.toHexString(pair.getPrivate().getEncoded()));
            System.out.println("Encoded public key: " + Hex.toHexString(pair.getPublic().getEncoded()));
            openpgp.putKey(KeyRef.SIG, PrivateKeyValues.fromPrivateKey(pair.getPrivate()));

            PublicKey publicKey = openpgp.getPublicKey(KeyRef.SIG).toPublicKey();
            openpgp.verifyUserPin("123456", false);
            byte[] signature = openpgp.sign(message);
            System.out.println("Signature: " + Hex.toHexString(signature));

            Signature verifier = Signature.getInstance("NONEwithECDSA");
            verifier.initVerify(publicKey);
            verifier.update(message);
            assert verifier.verify(signature);

            openpgp.putKey(KeyRef.DEC, PrivateKeyValues.fromPrivateKey(pair.getPrivate()));
            KeyPair pair2 = kpg.generateKeyPair();
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(pair2.getPrivate());
            ka.doPhase(openpgp.getPublicKey(KeyRef.DEC).toPublicKey(), true);
            byte[] expected = ka.generateSecret();

            openpgp.verifyUserPin("123456", true);
            byte[] agreement = openpgp.decrypt(PublicKeyValues.fromPublicKey(pair2.getPublic()));

            assert Arrays.equals(expected, agreement);
        }
    }

    public static void testImportEd25519Keys(OpenPgpSession openpgp) throws Exception {
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        openpgp.verifyAdminPin("12345678");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair pair = kpg.generateKeyPair();
        System.out.println("Encoded private key: " + Hex.toHexString(pair.getPrivate().getEncoded()));
        System.out.println("Encoded public key: " + Hex.toHexString(pair.getPublic().getEncoded()));
        openpgp.putKey(KeyRef.SIG, PrivateKeyValues.fromPrivateKey(pair.getPrivate()));

        byte[] message = "hello".getBytes(StandardCharsets.UTF_8);

        openpgp.verifyUserPin("123456", false);
        byte[] signature = openpgp.sign(message);
        System.out.println("Signature: " + Hex.toHexString(signature));

        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(openpgp.getPublicKey(KeyRef.SIG).toPublicKey());
        verifier.update(message);
        assert verifier.verify(signature);
    }

    public static void testImportX25519Keys(OpenPgpSession openpgp) throws Exception {
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        openpgp.verifyAdminPin("12345678");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair pair = kpg.generateKeyPair();
        System.out.println("Encoded private key: " + Hex.toHexString(pair.getPrivate().getEncoded()));
        System.out.println("Encoded public key: " + Hex.toHexString(pair.getPublic().getEncoded()));
        openpgp.putKey(KeyRef.DEC, PrivateKeyValues.fromPrivateKey(pair.getPrivate()));
        //Assert.assertArrayEquals(pair.getPublic().getEncoded(), openpgp.getPublicKey(KeyRef.DEC).toPublicKey().getEncoded());

        KeyPair pair2 = kpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(pair2.getPrivate());
        ka.doPhase(openpgp.getPublicKey(KeyRef.DEC).toPublicKey(), true);
        byte[] expected = ka.generateSecret();

        openpgp.verifyUserPin("123456", true);
        byte[] agreement = openpgp.decrypt(PublicKeyValues.Ec.fromPublicKey(pair2.getPublic()));

        assert Arrays.equals(expected, agreement);
    }

    public static void testStuff(OpenPgpSession openpgp) throws Exception {
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        OpenPgpAid aid = openpgp.getAid();
        System.out.println("AID: " + Hex.toHexString(aid.getBytes()));

        System.out.println("Serial from AID: " + aid.getSerial());
        logger.debug("AID is: {}", Hex.toHexString(aid.getBytes()));

        openpgp.verifyUserPin("123456", false);
        openpgp.verifyAdminPin("12345678");
        PublicKey key = openpgp.generateRsaKey(KeyRef.SIG, 2048).toPublicKey();
        System.out.println("Generated key: " + key);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "BC");
        //ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("Ed25519");
        //kpg.initialize(ecGenParameterSpec);
        KeyPair kp = kpg.generateKeyPair();


        /*
        Signature sig = Signature.getInstance("EdDSA");
        sig.initSign(kp.getPrivate());
        byte[] message = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        sig.update(message);
        byte[] signature = sig.sign();

        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
        key = keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        Signature ver = Signature.getInstance("EdDSA");
        ver.initVerify(key);
        ver.update(message);
        boolean res = ver.verify(signature);
        assert res;
        System.out.println("Signature verified!");
         */

        byte[] encoded = kpg.generateKeyPair().getPublic().getEncoded();
        System.out.println("PubKey 1: " + Hex.toHexString(encoded));
        encoded = kpg.generateKeyPair().getPublic().getEncoded();
        System.out.println("PubKey 2: " + Hex.toHexString(encoded));
        key = kpg.generateKeyPair().getPublic();
        System.out.println("Software key: " + key);
        //System.out.println("PubKey:" + ((ECPublicKey)key).getParams());

        KeyFactory keyFactory = KeyFactory.getInstance("X25519");
        key = keyFactory.generatePublic(new X509EncodedKeySpec(key.getEncoded()));
        System.out.println("Spec key: " + key);

        PublicKeyValues values = openpgp.generateEcKey(KeyRef.DEC, OpenPgpCurve.X25519);
        System.out.println("Generated encoded: " + Hex.toHexString(values.getEncoded()));
        key = values.toPublicKey();
        System.out.println("Generated key: " + key);

    }
}

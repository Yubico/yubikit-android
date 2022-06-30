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
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.ManagementKeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;
import com.yubico.yubikit.piv.jca.PivAlgorithmParameterSpec;
import com.yubico.yubikit.piv.jca.PivKeyStoreKeyParameters;
import com.yubico.yubikit.piv.jca.PivProvider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;

public class PivJcaDeviceTests {
    private static final byte[] DEFAULT_MANAGEMENT_KEY = Hex.decode("010203040506070801020304050607080102030405060708");
    private static final char[] DEFAULT_PIN = "123456".toCharArray();

    public static void setupJCA(PivSession piv) {
        Security.addProvider(new PivProvider(piv));
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
        listJCAProviders();
    }

    public static void tearDownJCA() {
        Security.removeProvider("YKPiv");
    }

    public static void listJCAProviders() {
        Provider[] providers = Security.getProviders();

        for (Provider p : providers) {
            String providerInfo = p.getName() + "/" + p.getInfo() + "/" + p.getVersion();
            Logger.d(providerInfo);
            Set<Provider.Service> services = p.getServices();
            for (Provider.Service s : services) {
                String serviceInfo = p.getName() + ":" + s.getType() + "/" + s.getAlgorithm() + "/" + s.getClassName();
                Logger.d(serviceInfo);
            }
        }
    }

    public static void testImportKeys(PivSession piv) throws Exception {
        setupJCA(piv);
        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);

        KeyStore keyStore = KeyStore.getInstance("YKPiv");
        keyStore.load(null);

        for (KeyType keyType : Arrays.asList(KeyType.RSA1024, KeyType.RSA2048)) {
            String alias = Slot.SIGNATURE.getStringAlias();

            KeyPair keyPair = PivTestUtils.loadKey(keyType);
            X509Certificate cert = PivTestUtils.createCertificate(keyPair);
            keyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new Certificate[]{cert}), new PivKeyStoreKeyParameters(PinPolicy.DEFAULT, TouchPolicy.DEFAULT));
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, DEFAULT_PIN);

            PivTestUtils.rsaEncryptAndDecrypt(privateKey, keyPair.getPublic());
            PivTestUtils.rsaSignAndVerify(privateKey, keyPair.getPublic());
            privateKey.destroy();
        }

        for (KeyType keyType : Arrays.asList(KeyType.ECCP256, KeyType.ECCP384)) {
            String alias = "9c";

            KeyPair keyPair = PivTestUtils.loadKey(keyType);
            X509Certificate cert = PivTestUtils.createCertificate(keyPair);

            keyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new Certificate[]{cert}), new PivKeyStoreKeyParameters(PinPolicy.DEFAULT, TouchPolicy.DEFAULT));
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, DEFAULT_PIN);

            PivTestUtils.ecKeyAgreement(privateKey, keyPair.getPublic());
            PivTestUtils.ecSignAndVerify(privateKey, keyPair.getPublic());
            privateKey.destroy();

            Assert.assertEquals(cert, keyStore.getCertificate(keyStore.getCertificateAlias(cert)));
        }

        tearDownJCA();
    }

    public static void testGenerateKeys(PivSession piv) throws Exception {
        setupJCA(piv);
        piv.authenticate(ManagementKeyType.TDES, DEFAULT_MANAGEMENT_KEY);

        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("YKPivEC");
        for (KeyType keyType : Arrays.asList(KeyType.ECCP256, KeyType.ECCP384)) {
            ecGen.initialize(new PivAlgorithmParameterSpec(Slot.AUTHENTICATION, keyType, null, null, DEFAULT_PIN));
            KeyPair keyPair = ecGen.generateKeyPair();
            PivTestUtils.ecSignAndVerify(keyPair.getPrivate(), keyPair.getPublic());
            PivTestUtils.ecKeyAgreement(keyPair.getPrivate(), keyPair.getPublic());
            //TODO: Test with key loaded from KeyStore
        }

        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("YKPivRSA");
        for (KeyType keyType : Arrays.asList(KeyType.RSA1024, KeyType.RSA2048)) {
            rsaGen.initialize(new PivAlgorithmParameterSpec(Slot.AUTHENTICATION, keyType, null, null, DEFAULT_PIN));
            KeyPair keyPair = rsaGen.generateKeyPair();
            PivTestUtils.rsaEncryptAndDecrypt(keyPair.getPrivate(), keyPair.getPublic());
            PivTestUtils.rsaSignAndVerify(keyPair.getPrivate(), keyPair.getPublic());
            //TODO: Test with key loaded from KeyStore
        }
        tearDownJCA();
    }
}

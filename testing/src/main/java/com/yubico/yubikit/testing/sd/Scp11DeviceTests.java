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

package com.yubico.yubikit.testing.sd;

import static com.yubico.yubikit.testing.sd.Scp11TestData.OCE_CERTS_V1;
import static com.yubico.yubikit.testing.sd.Scp11TestData.OCE_CERTS_V2;
import static com.yubico.yubikit.testing.sd.Scp11TestData.OCE_V1;
import static com.yubico.yubikit.testing.sd.Scp11TestData.OCE_V1_PASSWORD;
import static com.yubico.yubikit.testing.sd.Scp11TestData.OCE_V2;
import static com.yubico.yubikit.testing.sd.Scp11TestData.OCE_V2_PASSWORD;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.scp.KeyRef;
import com.yubico.yubikit.core.smartcard.scp.Scp03KeyParams;
import com.yubico.yubikit.core.smartcard.scp.Scp11KeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;
import com.yubico.yubikit.core.smartcard.scp.StaticKeys;
import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.core.util.Tlv;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

public class Scp11DeviceTests {

    static final KeyRef defaultRef = new KeyRef((byte) 0x01, (byte) 0xff);
    static final KeyRef AUTH_SCP03_KEY = new KeyRef((byte) 0x01, (byte) 0x01);
    static final KeyRef AUTH_SCP11A_KEY = new KeyRef(ScpKid.SCP11a, (byte) 2);
    static final KeyRef CA_KLOC_KEY_REF = new KeyRef((byte) 0x10, (byte) 2);

    public static void before(SecurityDomainTestState state) throws Throwable {
        assumeTrue("Device does not support SCP11a",
                state.getDeviceInfo().getVersion().isAtLeast(5, 7, 2));
        state.withSecurityDomain(SecurityDomainSession::reset);
    }

    public static void testScp11aImportKey(SecurityDomainTestState state) throws Throwable {
        testScp11aImportKey(state, OCE_CERTS_V1, OCE_V1, OCE_V1_PASSWORD);
    }

    public static void testScp11aImportKeyAlt(SecurityDomainTestState state) throws Throwable {
        testScp11aImportKey(state, OCE_CERTS_V2, OCE_V2, OCE_V2_PASSWORD);
    }

    private static void testScp11aImportKey(
            SecurityDomainTestState state,
            byte[] oceCerts,
            byte[] oce,
            char[] password) throws Throwable {

        state.withSecurityDomain(SecurityDomainSession::reset);

        // replace default SCP03 keys so that we can authenticate later
        ScpKeyParams scp03KeyParams = replaceDefaultScp03Key(state);

        PublicKeyValues pk = state.withSecurityDomain(scp03KeyParams, session -> {
            return setupScp11a(session, oceCerts);
        });

        // direct auth
        state.withSecurityDomain(
                getScp11aKeyParams(oce, password, pk.toPublicKey()),
                session -> {
                    Map<KeyRef, Map<Byte, Byte>> keyInformation = session.getKeyInformation();
                    assertNotNull(keyInformation.get(AUTH_SCP11A_KEY));
                });

        // read public key and auth
        state.withSecurityDomain(session -> {
            List<X509Certificate> certs = session.getCertificateBundle(AUTH_SCP11A_KEY);
            PublicKey publicKey = certs.get(certs.size() - 1).getPublicKey();
            ScpKeyParams params = getScp11aKeyParams(oce, password, publicKey);
            session.authenticate(params);
            Map<KeyRef, Map<Byte, Byte>> keyInformation = session.getKeyInformation();
            assertNotNull(keyInformation.get(AUTH_SCP11A_KEY));
        });

        // read public key and then auth
        PublicKey publicKey = state.withSecurityDomain(session -> {
            List<X509Certificate> certs = session.getCertificateBundle(AUTH_SCP11A_KEY);
            return certs.get(certs.size() - 1).getPublicKey();
        });

        state.withSecurityDomain(
                getScp11aKeyParams(oce, password, publicKey),
                session -> {
                    Map<KeyRef, Map<Byte, Byte>> keyInformation = session.getKeyInformation();
                    assertNotNull(keyInformation.get(AUTH_SCP11A_KEY));
                });
    }

    private static final ScpKeyParams defaultScp03KeyParams =
            new Scp03KeyParams(defaultRef, StaticKeys.getDefaultKeys());

    public static void testScp11aAuthenticate(SecurityDomainTestState state) throws Throwable {
        final byte kvn = 0x03;

        ScpKeyParams keyParams = state.withSecurityDomain(defaultScp03KeyParams, session -> {
            return loadKeys(session, ScpKid.SCP11a, kvn);
        });

        state.withSecurityDomain(keyParams, session -> {
            session.deleteKey(new KeyRef(ScpKid.SCP11a, kvn), false);
        });
    }

    public static void testScp11aAllowList(SecurityDomainTestState state) throws Throwable {
        final byte kvn = 0x05;

        ScpKeyParams keyParams = state.withSecurityDomain(defaultScp03KeyParams, session -> {
            Scp11KeyParams params = loadKeys(session, ScpKid.SCP11a, kvn);
            assertNotNull(params.getOceKeyRef());

            List<BigInteger> serials = new ArrayList<>();
            for (X509Certificate cert : params.getCertificates()) {
                serials.add(cert.getSerialNumber());
            }

            session.storeAllowlist(params.getOceKeyRef(), serials);
            return params;
        });

        state.withSecurityDomain(keyParams, session -> {
            session.deleteKey(new KeyRef(ScpKid.SCP11a, kvn), false);
        });
    }

    public static void testScp11aAllowListBlocked(SecurityDomainTestState state) throws Throwable {
        final byte kvn = 0x03;

        ScpKeyParams scp03KeyParams = replaceDefaultScp03Key(state);

        Scp11KeyParams keyParams = state.withSecurityDomain(scp03KeyParams, session -> {
            session.deleteKey(new KeyRef(ScpKid.SCP11b, (byte) 1), false);

            Scp11KeyParams scp11KeyParams = loadKeys(session, ScpKid.SCP11a, kvn);
            assertNotNull(scp11KeyParams.getOceKeyRef());

            final List<BigInteger> serials = Arrays.asList(
                    BigInteger.valueOf(1), BigInteger.valueOf(2), BigInteger.valueOf(3),
                    BigInteger.valueOf(4), BigInteger.valueOf(5));

            session.storeAllowlist(scp11KeyParams.getOceKeyRef(), serials);

            return scp11KeyParams;
        });

        // authenticate with scp11a will throw
        state.withSecurityDomain(session -> {
            assertThrows(ApduException.class, () -> session.authenticate(keyParams));
        });

        // reset the allow list
        state.withSecurityDomain(scp03KeyParams, session -> {
            assertNotNull(keyParams.getOceKeyRef());
            session.storeAllowlist(keyParams.getOceKeyRef(), new ArrayList<>());
        });

        // authenticate with scp11a will not throw
        state.withSecurityDomain(session -> {
            session.authenticate(keyParams);
        });
    }

    public static void testScp11bAuthenticate(SecurityDomainTestState state) throws Throwable {
        final KeyRef ref = new KeyRef(ScpKid.SCP11b, (byte) 0x1);

        List<X509Certificate> chain = state.withSecurityDomain(defaultScp03KeyParams, session -> {
            return session.getCertificateBundle(ref);
        });

        X509Certificate leaf = chain.get(chain.size() - 1);
        Scp11KeyParams params = new Scp11KeyParams(ref, leaf.getPublicKey());

        state.withSecurityDomain(params, session -> {
            assertThrows(ApduException.class, () -> verifyScp11bAuth(session));
        });
    }

    public static void testScp11bWrongPubKey(SecurityDomainTestState state) throws Throwable {
        final KeyRef ref = new KeyRef(ScpKid.SCP11b, (byte) 0x1);

        List<X509Certificate> chain = state.withSecurityDomain(defaultScp03KeyParams, session -> {
            return session.getCertificateBundle(ref);
        });

        X509Certificate cert = chain.get(0);
        Scp11KeyParams params = new Scp11KeyParams(ref, cert.getPublicKey());

        state.withSecurityDomain(session -> {
            BadResponseException e =
                    assertThrows(BadResponseException.class, () -> session.authenticate(params));
            assertEquals("Receipt does not match", e.getMessage());
        });
    }

    public static void testScp11bImport(SecurityDomainTestState state) throws Throwable {
        final KeyRef ref = new KeyRef(ScpKid.SCP11b, (byte) 0x2);

        ScpKeyParams keyParams = state.withSecurityDomain(session -> {
            session.authenticate(defaultScp03KeyParams);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecParams = new ECGenParameterSpec("secp256r1");
            kpg.initialize(ecParams);
            KeyPair keyPair = kpg.generateKeyPair();
            session.putKey(ref, PrivateKeyValues.fromPrivateKey(keyPair.getPrivate()), 0);
            return new Scp11KeyParams(ref, keyPair.getPublic());
        });

        state.withSecurityDomain(session -> {
            session.authenticate(keyParams);
        });
    }

    private static void verifyScp11bAuth(SecurityDomainSession session)
            throws BadResponseException, ApduException, IOException {
        KeyRef ref = new KeyRef(ScpKid.SCP11b, (byte) 0x7f);
        session.generateEcKey(ref, 0);
        session.deleteKey(ref, false);
    }

    public static void testScp11cAuthenticate(SecurityDomainTestState state) throws Throwable {
        final byte kvn = 0x03;

        ScpKeyParams keyParams = state.withSecurityDomain(defaultScp03KeyParams, session -> {
            return loadKeys(session, ScpKid.SCP11c, kvn);
        });

        state.withSecurityDomain(keyParams, session -> {
            assertThrows(ApduException.class, () ->
                    session.deleteKey(new KeyRef(ScpKid.SCP11c, kvn), false));
        });
    }

    private static ScpKeyParams replaceDefaultScp03Key(SecurityDomainTestState state) throws Throwable {
        assumeFalse("SCP03 management not supported over NFC on FIPS capable devices",
                state.getDeviceInfo().getFipsCapable() != 0 && !state.isUsbTransport());

        final StaticKeys staticKeys = new StaticKeys(
                RandomUtils.getRandomBytes(16),
                RandomUtils.getRandomBytes(16),
                RandomUtils.getRandomBytes(16)
        );

        state.withSecurityDomain(session -> {
            session.authenticate(defaultScp03KeyParams);
            session.putKey(AUTH_SCP03_KEY, staticKeys, 0);
        });

        return new Scp03KeyParams(AUTH_SCP03_KEY, staticKeys);
    }

    private static Scp11KeyParams getScp11aKeyParams(byte[] pkcs12, char[] password, PublicKey pk)
            throws Throwable {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try (InputStream is = new ByteArrayInputStream(pkcs12)) {
            keyStore.load(is, password);

            final Enumeration<String> aliases = keyStore.aliases();
            assertTrue(aliases.hasMoreElements());
            String alias = keyStore.aliases().nextElement();
            assertTrue(keyStore.isKeyEntry(alias));

            Key sk = keyStore.getKey(keyStore.aliases().nextElement(), password);
            assertTrue("No private key in pkcs12", sk instanceof PrivateKey);

            ScpCertificates certs = ScpCertificates.from(getCertificateChain(keyStore, alias));

            List<X509Certificate> certChain = new ArrayList<>(certs.bundle);
            if (certs.leaf != null) {
                certChain.add(certs.leaf);
            }

            return new Scp11KeyParams(
                    AUTH_SCP11A_KEY,
                    pk,
                    CA_KLOC_KEY_REF,
                    (PrivateKey) sk,
                    certChain
            );
        }
    }

    @SuppressWarnings("unchecked")
    private static ScpCertificates getOceCertificates(byte[] pem)
            throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try (InputStream is = new ByteArrayInputStream(pem)) {
            return ScpCertificates.from((List<X509Certificate>) certificateFactory.generateCertificates(is));
        }
    }

    private static byte[] getSki(X509Certificate certificate) {
        byte[] skiExtensionValue = certificate.getExtensionValue("2.5.29.14");
        if (skiExtensionValue == null) {
            return null;
        }
        assertNotNull("Missing Subject Key Identifier", skiExtensionValue);
        Tlv tlv = Tlv.parse(skiExtensionValue);
        assertEquals("Invalid extension value", 0x04, tlv.getTag());
        Tlv digest = Tlv.parse(tlv.getValue());
        assertEquals("Invalid Subject Key Identifier", 0x04, digest.getTag());
        return digest.getValue();
    }

    private static List<X509Certificate> getCertificateChain(KeyStore keyStore, String alias)
            throws KeyStoreException {
        Certificate[] chain = keyStore.getCertificateChain(alias);
        final List<X509Certificate> certificateChain = new ArrayList<>();
        for (Certificate cert : chain) {
            if (cert instanceof X509Certificate) {
                certificateChain.add((X509Certificate) cert);
            }
        }
        return certificateChain;
    }

    private static PublicKeyValues setupScp11a(SecurityDomainSession session, byte[] pem)
            throws Throwable {
        // generate new SCP11a key
        PublicKeyValues generatedPk = session.generateEcKey(AUTH_SCP11A_KEY, 0);

        // delete default SCP11b key
        session.deleteKey(new KeyRef(ScpKid.SCP11b, (byte) 1), false);

        // import OCE CA-KLOC certificate
        ScpCertificates certs = getOceCertificates(pem);

        if (certs.ca == null) {
            fail("Input does not contain valid CA-KLOC certificate");
        }

        session.putKey(CA_KLOC_KEY_REF, PublicKeyValues.fromPublicKey(certs.ca.getPublicKey()), 0);

        byte[] ski = getSki(certs.ca);
        assertNotNull("CA certificate missing Subject Key Identifier", ski);
        session.storeCaIssuer(CA_KLOC_KEY_REF, ski);

        // delete our SCP03 keys
        session.deleteKey(AUTH_SCP03_KEY, false);

        return generatedPk;
    }

    private static Scp11KeyParams loadKeys(SecurityDomainSession session, byte kid, byte kvn)
            throws Throwable {
        KeyRef sessionRef = new KeyRef(kid, kvn);
        KeyRef oceRef = new KeyRef((byte) 0x10, kvn);

        PublicKeyValues publicKeyValues = session.generateEcKey(sessionRef, 0);

        ScpCertificates oceCerts = getOceCertificates(OCE_CERTS_V1);
        assertNotNull("Missing CA", oceCerts.ca);
        session.putKey(oceRef, PublicKeyValues.fromPublicKey(oceCerts.ca.getPublicKey()), 0);

        byte[] ski = getSki(oceCerts.ca);
        assertNotNull("CA certificate missing Subject Key Identifier", ski);
        session.storeCaIssuer(oceRef, ski);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try (InputStream is = new ByteArrayInputStream(OCE_V1)) {
            keyStore.load(is, OCE_V1_PASSWORD);

            final Enumeration<String> aliases = keyStore.aliases();
            assertTrue(aliases.hasMoreElements());
            String alias = keyStore.aliases().nextElement();
            assertTrue(keyStore.isKeyEntry(alias));

            Key sk = keyStore.getKey(keyStore.aliases().nextElement(), OCE_V1_PASSWORD);
            assertTrue("No private key in pkcs12", sk instanceof PrivateKey);

            ScpCertificates certs = ScpCertificates.from(getCertificateChain(keyStore, alias));

            List<X509Certificate> certChain = new ArrayList<>(certs.bundle);
            if (certs.leaf != null) {
                certChain.add(certs.leaf);
            }

            return new Scp11KeyParams(
                    sessionRef,
                    publicKeyValues.toPublicKey(),
                    oceRef,
                    (PrivateKey) sk,
                    certChain
            );
        }
    }
}

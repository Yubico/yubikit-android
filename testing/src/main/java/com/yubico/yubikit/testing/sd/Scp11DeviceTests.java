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

package com.yubico.yubikit.testing.sd;

import static com.yubico.yubikit.testing.sd.Scp11TestData.OCE;
import static com.yubico.yubikit.testing.sd.Scp11TestData.OCE_CERTS;
import static com.yubico.yubikit.testing.sd.Scp11TestData.OCE_PASSWORD;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

public class Scp11DeviceTests {
  private static final ScpKeyParams defaultKeyParams =
      new Scp03KeyParams(new KeyRef((byte) 0x01, (byte) 0xff), StaticKeys.getDefaultKeys());

  private static final byte OCE_KID = 0x010;

  public static void before(SecurityDomainTestState state) throws Throwable {
    assumeTrue(
        "Device does not support SCP11a", state.getDeviceInfo().getVersion().isAtLeast(5, 7, 2));
    assumeFalse(
        "SCP03 authentication not supported over NFC on FIPS capable devices",
        state.getDeviceInfo().getFipsCapable() != 0 && !state.isUsbTransport());
    state.withSecurityDomain(SecurityDomainSession::reset);
  }

  public static void testScp11aAuthenticate(SecurityDomainTestState state) throws Throwable {
    final byte kvn = 0x03;

    ScpKeyParams keyParams =
        state.withSecurityDomain(
            defaultKeyParams,
            session -> {
              return loadKeys(session, ScpKid.SCP11a, kvn);
            });

    state.withSecurityDomain(
        keyParams,
        session -> {
          session.deleteKey(new KeyRef(ScpKid.SCP11a, kvn), false);
        });
  }

  public static void testScp11aAllowList(SecurityDomainTestState state) throws Throwable {
    final byte kvn = 0x05;
    final KeyRef oceKeyRef = new KeyRef(OCE_KID, kvn);

    ScpKeyParams keyParams =
        state.withSecurityDomain(
            defaultKeyParams,
            session -> {
              return loadKeys(session, ScpKid.SCP11a, kvn);
            });

    state.withSecurityDomain(
        keyParams,
        session -> {
          final List<BigInteger> serials =
              Arrays.asList(
                  // serial numbers from OCE
                  new BigInteger("7f4971b0ad51f84c9da9928b2d5fef5e16b2920a", 16),
                  new BigInteger("6b90028800909f9ffcd641346933242748fbe9ad", 16));
          session.storeAllowlist(oceKeyRef, serials);
        });

    state.withSecurityDomain(
        keyParams,
        session -> {
          session.deleteKey(new KeyRef(ScpKid.SCP11a, kvn), false);
        });
  }

  public static void testScp11aAllowListBlocked(SecurityDomainTestState state) throws Throwable {
    final byte kvn = 0x03;
    final KeyRef oceKeyRef = new KeyRef(OCE_KID, kvn);

    ScpKeyParams scp03KeyParams = importScp03Key(state);

    Scp11KeyParams keyParams =
        state.withSecurityDomain(
            scp03KeyParams,
            session -> {
              // make space for new key
              session.deleteKey(new KeyRef(ScpKid.SCP11b, (byte) 1), false);

              Scp11KeyParams scp11KeyParams = loadKeys(session, ScpKid.SCP11a, kvn);

              final List<BigInteger> serials =
                  Arrays.asList(
                      BigInteger.valueOf(1),
                      BigInteger.valueOf(2),
                      BigInteger.valueOf(3),
                      BigInteger.valueOf(4),
                      BigInteger.valueOf(5));

              session.storeAllowlist(oceKeyRef, serials);

              return scp11KeyParams;
            });

    // authenticate with scp11a will throw
    state.withSecurityDomain(
        session -> {
          assertThrows(ApduException.class, () -> session.authenticate(keyParams));
        });

    // reset the allow list
    state.withSecurityDomain(
        scp03KeyParams,
        session -> {
          session.storeAllowlist(oceKeyRef, new ArrayList<>());
        });

    // authenticate with scp11a will not throw
    state.withSecurityDomain(
        session -> {
          session.authenticate(keyParams);
        });
  }

  public static void testScp11bAuthenticate(SecurityDomainTestState state) throws Throwable {
    final KeyRef ref = new KeyRef(ScpKid.SCP11b, (byte) 0x1);

    List<X509Certificate> chain =
        state.withSecurityDomain(
            defaultKeyParams,
            session -> {
              return session.getCertificateBundle(ref);
            });

    X509Certificate leaf = chain.get(chain.size() - 1);
    Scp11KeyParams params = new Scp11KeyParams(ref, leaf.getPublicKey());

    state.withSecurityDomain(
        params,
        session -> {
          assertThrows(ApduException.class, () -> verifyScp11bAuth(session));
        });
  }

  public static void testScp11bWrongPubKey(SecurityDomainTestState state) throws Throwable {
    final KeyRef ref = new KeyRef(ScpKid.SCP11b, (byte) 0x1);

    List<X509Certificate> chain =
        state.withSecurityDomain(
            defaultKeyParams,
            session -> {
              return session.getCertificateBundle(ref);
            });

    X509Certificate cert = chain.get(0);
    Scp11KeyParams params = new Scp11KeyParams(ref, cert.getPublicKey());

    state.withSecurityDomain(
        session -> {
          BadResponseException e =
              assertThrows(BadResponseException.class, () -> session.authenticate(params));
          assertEquals("Receipt does not match", e.getMessage());
        });
  }

  public static void testScp11bImport(SecurityDomainTestState state) throws Throwable {
    final KeyRef ref = new KeyRef(ScpKid.SCP11b, (byte) 0x2);

    ScpKeyParams keyParams =
        state.withSecurityDomain(
            session -> {
              session.authenticate(defaultKeyParams);
              KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
              ECGenParameterSpec ecParams = new ECGenParameterSpec("secp256r1");
              kpg.initialize(ecParams);
              KeyPair keyPair = kpg.generateKeyPair();
              session.putKey(ref, PrivateKeyValues.fromPrivateKey(keyPair.getPrivate()), 0);
              return new Scp11KeyParams(ref, keyPair.getPublic());
            });

    state.withSecurityDomain(
        session -> {
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

    ScpKeyParams keyParams =
        state.withSecurityDomain(
            defaultKeyParams,
            session -> {
              return loadKeys(session, ScpKid.SCP11c, kvn);
            });

    state.withSecurityDomain(
        keyParams,
        session -> {
          assertThrows(
              ApduException.class, () -> session.deleteKey(new KeyRef(ScpKid.SCP11c, kvn), false));
        });
  }

  private static ScpKeyParams importScp03Key(SecurityDomainTestState state) throws Throwable {
    assumeFalse(
        "SCP03 management not supported over NFC on FIPS capable devices",
        state.getDeviceInfo().getFipsCapable() != 0 && !state.isUsbTransport());

    final KeyRef scp03Ref = new KeyRef((byte) 0x01, (byte) 0x01);

    final StaticKeys staticKeys =
        new StaticKeys(
            RandomUtils.getRandomBytes(16),
            RandomUtils.getRandomBytes(16),
            RandomUtils.getRandomBytes(16));

    state.withSecurityDomain(
        session -> {
          session.authenticate(defaultKeyParams);
          session.putKey(scp03Ref, staticKeys, 0);
        });

    return new Scp03KeyParams(scp03Ref, staticKeys);
  }

  @SuppressWarnings({"unchecked", "SameParameterValue"})
  private static ScpCertificates getOceCertificates(byte[] pem)
      throws CertificateException, IOException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    try (InputStream is = new ByteArrayInputStream(pem)) {
      return ScpCertificates.from(
          (List<X509Certificate>) certificateFactory.generateCertificates(is));
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

  private static Scp11KeyParams loadKeys(SecurityDomainSession session, byte kid, byte kvn)
      throws Throwable {
    KeyRef sessionRef = new KeyRef(kid, kvn);
    KeyRef oceRef = new KeyRef(OCE_KID, kvn);

    PublicKeyValues publicKeyValues = session.generateEcKey(sessionRef, 0);

    ScpCertificates oceCerts = getOceCertificates(OCE_CERTS);
    assertNotNull("Missing CA", oceCerts.ca);
    session.putKey(oceRef, PublicKeyValues.fromPublicKey(oceCerts.ca.getPublicKey()), 0);

    byte[] ski = getSki(oceCerts.ca);
    assertNotNull("CA certificate missing Subject Key Identifier", ski);
    session.storeCaIssuer(oceRef, ski);

    KeyStore keyStore = KeyStore.getInstance("PKCS12");

    try (InputStream is = new ByteArrayInputStream(OCE)) {
      keyStore.load(is, OCE_PASSWORD);

      PrivateKey sk = getPrivateKey(keyStore);
      ScpCertificates certs = getCertificates(keyStore);

      List<X509Certificate> certChain = new ArrayList<>(certs.bundle);
      if (certs.leaf != null) {
        certChain.add(certs.leaf);
      }

      return new Scp11KeyParams(sessionRef, publicKeyValues.toPublicKey(), oceRef, sk, certChain);
    }
  }

  static PrivateKey getPrivateKey(KeyStore keyStore) throws Throwable {
    final Enumeration<String> aliases = keyStore.aliases();
    assertTrue(aliases.hasMoreElements());
    String alias = keyStore.aliases().nextElement();
    assertTrue(keyStore.isKeyEntry(alias));

    Key sk = keyStore.getKey(keyStore.aliases().nextElement(), OCE_PASSWORD);
    assertTrue("No private key in pkcs12", sk instanceof PrivateKey);

    return (PrivateKey) sk;
  }

  static ScpCertificates getCertificates(KeyStore keyStore) throws Throwable {
    final Enumeration<String> aliases = keyStore.aliases();
    assertTrue(aliases.hasMoreElements());
    String alias = keyStore.aliases().nextElement();
    assertTrue(keyStore.isKeyEntry(alias));

    Key sk = keyStore.getKey(keyStore.aliases().nextElement(), OCE_PASSWORD);
    assertTrue("No private key in pkcs12", sk instanceof PrivateKey);

    return ScpCertificates.from(getCertificateChain(keyStore, alias));
  }
}

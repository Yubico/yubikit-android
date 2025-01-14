/*
 * Copyright (C) 2020-2022,2024 Yubico.
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

import static com.yubico.yubikit.piv.PivSession.FEATURE_CV25519;
import static com.yubico.yubikit.piv.PivSession.FEATURE_P384;
import static com.yubico.yubikit.piv.PivSession.FEATURE_RSA3072_RSA4096;
import static com.yubico.yubikit.testing.piv.PivJcaUtils.setupJca;
import static com.yubico.yubikit.testing.piv.PivJcaUtils.tearDownJca;

import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;
import com.yubico.yubikit.piv.jca.PivAlgorithmParameterSpec;
import com.yubico.yubikit.piv.jca.PivKeyStoreKeyParameters;
import com.yubico.yubikit.piv.jca.PivProvider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.security.auth.Destroyable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;

public class PivJcaDeviceTests {

  @SuppressWarnings("NewApi") // casting to Destroyable is supported from API 26
  public static void testImportKeys(PivSession piv, PivTestState state) throws Exception {
    setupJca(piv);
    piv.authenticate(state.managementKey);

    KeyStore keyStore = KeyStore.getInstance("YKPiv");
    keyStore.load(null);

    for (KeyType keyType :
        Arrays.asList(KeyType.RSA1024, KeyType.RSA2048, KeyType.RSA3072, KeyType.RSA4096)) {

      if (state.isInvalidKeyType(keyType)) {
        continue;
      }

      if (!piv.supports(FEATURE_RSA3072_RSA4096)
          && (keyType == KeyType.RSA3072 || keyType == KeyType.RSA4096)) {
        continue;
      }

      String alias = Slot.SIGNATURE.getStringAlias();

      KeyPair keyPair = PivTestUtils.loadKey(keyType);
      X509Certificate cert = PivTestUtils.createCertificate(keyPair);
      keyStore.setEntry(
          alias,
          new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new Certificate[] {cert}),
          new PivKeyStoreKeyParameters(PinPolicy.DEFAULT, TouchPolicy.DEFAULT));
      PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, state.pin);

      PivTestUtils.rsaEncryptAndDecrypt(privateKey, keyPair.getPublic());
      PivTestUtils.rsaSignAndVerify(privateKey, keyPair.getPublic());

      //noinspection RedundantCast
      ((Destroyable) privateKey).destroy();
    }

    for (KeyType keyType : Arrays.asList(KeyType.ECCP256, KeyType.ECCP384)) {

      if (!piv.supports(FEATURE_P384) && keyType == KeyType.ECCP384) {
        continue;
      }

      String alias = Slot.SIGNATURE.getStringAlias();

      KeyPair keyPair = PivTestUtils.loadKey(keyType);
      X509Certificate cert = PivTestUtils.createCertificate(keyPair);

      keyStore.setEntry(
          alias,
          new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new Certificate[] {cert}),
          new PivKeyStoreKeyParameters(PinPolicy.DEFAULT, TouchPolicy.DEFAULT));
      PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, state.pin);

      PivTestUtils.ecKeyAgreement(privateKey, keyPair.getPublic());
      PivTestUtils.ecSignAndVerify(privateKey, keyPair.getPublic());

      //noinspection RedundantCast
      ((Destroyable) privateKey).destroy();

      Assert.assertEquals(cert, keyStore.getCertificate(keyStore.getCertificateAlias(cert)));
    }

    if (piv.supports(FEATURE_CV25519)) {
      for (KeyType keyType : Arrays.asList(KeyType.ED25519, KeyType.X25519)) {

        if (state.isInvalidKeyType(keyType)) {
          continue;
        }

        String alias = Slot.SIGNATURE.getStringAlias();

        KeyPair keyPair = PivTestUtils.loadKey(keyType);
        X509Certificate cert = PivTestUtils.createCertificate(keyPair);

        keyStore.setEntry(
            alias,
            new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new Certificate[] {cert}),
            new PivKeyStoreKeyParameters(PinPolicy.DEFAULT, TouchPolicy.DEFAULT));
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, state.pin);

        if (keyType == KeyType.X25519) {
          PivTestUtils.x25519KeyAgreement(privateKey, keyPair.getPublic());
        }

        if (keyType == KeyType.ED25519) {
          PivTestUtils.ed25519SignAndVerify(privateKey, keyPair.getPublic());
        }

        //noinspection RedundantCast
        ((Destroyable) privateKey).destroy();

        Assert.assertEquals(cert, keyStore.getCertificate(keyStore.getCertificateAlias(cert)));
      }
    }

    tearDownJca();
  }

  public static void testGenerateKeys(PivSession piv, PivTestState state) throws Exception {
    setupJca(piv);
    generateKeys(piv, state);
    tearDownJca();
  }

  public static void testGenerateKeysPreferBC(PivSession piv, PivTestState state) throws Exception {
    // following is an alternate version of setupJca method
    // the Bouncy Castle provider is set on second position and will provide Ed25519 and X25519
    // cryptographic services on the host.
    Security.removeProvider("BC");
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    Security.insertProviderAt(new PivProvider(piv), 1);

    generateKeys(piv, state);
    tearDownJca();
  }

  private static void generateKeys(PivSession piv, PivTestState state) throws Exception {
    piv.authenticate(state.managementKey);

    KeyPairGenerator ecGen = KeyPairGenerator.getInstance("YKPivEC");
    for (KeyType keyType :
        Arrays.asList(KeyType.ECCP256, KeyType.ECCP384, KeyType.ED25519, KeyType.X25519)) {

      if (state.isInvalidKeyType(keyType)) {
        continue;
      }

      if (!piv.supports(FEATURE_P384) && keyType == KeyType.ECCP384) {
        continue;
      }

      if (!piv.supports(FEATURE_CV25519)
          && (keyType == KeyType.ED25519 || keyType == KeyType.X25519)) {
        continue;
      }

      ecGen.initialize(
          new PivAlgorithmParameterSpec(Slot.AUTHENTICATION, keyType, null, null, state.pin));
      KeyPair keyPair = ecGen.generateKeyPair();

      if (keyType == KeyType.ED25519) {
        PivTestUtils.ed25519SignAndVerify(keyPair.getPrivate(), keyPair.getPublic());
        continue;
      }

      if (keyType != KeyType.X25519) {
        PivTestUtils.ecSignAndVerify(keyPair.getPrivate(), keyPair.getPublic());
      }

      if (keyType != KeyType.X25519) {
        PivTestUtils.ecKeyAgreement(keyPair.getPrivate(), keyPair.getPublic());
      } else {
        PivTestUtils.x25519KeyAgreement(keyPair.getPrivate(), keyPair.getPublic());
      }
      // TODO: Test with key loaded from KeyStore
    }

    KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("YKPivRSA");
    for (KeyType keyType :
        Arrays.asList(KeyType.RSA1024, KeyType.RSA2048, KeyType.RSA3072, KeyType.RSA4096)) {

      if (state.isInvalidKeyType(keyType)) {
        continue;
      }

      if (!piv.supports(FEATURE_RSA3072_RSA4096)
          && (keyType == KeyType.RSA3072 || keyType == KeyType.RSA4096)) {
        continue;
      }

      rsaGen.initialize(
          new PivAlgorithmParameterSpec(Slot.AUTHENTICATION, keyType, null, null, state.pin));
      KeyPair keyPair = rsaGen.generateKeyPair();
      PivTestUtils.rsaEncryptAndDecrypt(keyPair.getPrivate(), keyPair.getPublic());
      PivTestUtils.rsaSignAndVerify(keyPair.getPrivate(), keyPair.getPublic());
      // TODO: Test with key loaded from KeyStore
    }
  }
}

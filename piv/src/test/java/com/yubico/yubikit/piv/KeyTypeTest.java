/*
 * Copyright (C) 2020-2024,2026 Yubico.
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
package com.yubico.yubikit.piv;

import com.yubico.yubikit.core.keys.PrivateKeyValues;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.BeforeClass;
import org.junit.Test;

public class KeyTypeTest {
  private static final SecureRandom secureRandom = new SecureRandom();

  private static KeyPair secp256r1;
  private static KeyPair secp384r1;
  private static KeyPair secp521r1;
  private static KeyPair rsa1024;
  private static KeyPair rsa2048;
  private static KeyPair rsa3072;
  private static KeyPair rsa4096;

  @BeforeClass
  public static void setupKeys()
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

    KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyType.Algorithm.EC.name());
    kpg.initialize(new ECGenParameterSpec("secp256r1"), secureRandom);
    secp256r1 = kpg.generateKeyPair();
    kpg.initialize(new ECGenParameterSpec("secp384r1"), secureRandom);
    secp384r1 = kpg.generateKeyPair();
    kpg.initialize(new ECGenParameterSpec("secp521r1"), secureRandom);
    secp521r1 = kpg.generateKeyPair();

    kpg = KeyPairGenerator.getInstance(KeyType.Algorithm.RSA.name());
    kpg.initialize(1024);
    rsa1024 = kpg.generateKeyPair();
    kpg.initialize(2048);
    rsa2048 = kpg.generateKeyPair();
    kpg.initialize(3072);
    rsa3072 = kpg.generateKeyPair();
    kpg.initialize(4096);
    rsa4096 = kpg.generateKeyPair();
  }

  @Test
  public void testFromEcKey() {
    MatcherAssert.assertThat(
        KeyType.fromKey(secp256r1.getPrivate()), CoreMatchers.is(KeyType.ECCP256));
    MatcherAssert.assertThat(
        KeyType.fromKey(secp256r1.getPublic()), CoreMatchers.is(KeyType.ECCP256));

    MatcherAssert.assertThat(
        KeyType.fromKey(secp384r1.getPrivate()), CoreMatchers.is(KeyType.ECCP384));
    MatcherAssert.assertThat(
        KeyType.fromKey(secp384r1.getPublic()), CoreMatchers.is(KeyType.ECCP384));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testP521R1Public() {
    KeyType.fromKey(secp521r1.getPublic());
  }

  @Test(expected = IllegalArgumentException.class)
  public void testP521R1Private() {
    KeyType.fromKey(secp521r1.getPrivate());
  }

  @Test
  public void testFromRsaKey() {
    MatcherAssert.assertThat(
        KeyType.fromKey(rsa1024.getPrivate()), CoreMatchers.is(KeyType.RSA1024));
    MatcherAssert.assertThat(
        KeyType.fromKey(rsa1024.getPublic()), CoreMatchers.is(KeyType.RSA1024));

    MatcherAssert.assertThat(
        KeyType.fromKey(rsa2048.getPrivate()), CoreMatchers.is(KeyType.RSA2048));
    MatcherAssert.assertThat(
        KeyType.fromKey(rsa2048.getPublic()), CoreMatchers.is(KeyType.RSA2048));

    MatcherAssert.assertThat(
        KeyType.fromKey(rsa3072.getPrivate()), CoreMatchers.is(KeyType.RSA3072));
    MatcherAssert.assertThat(
        KeyType.fromKey(rsa3072.getPublic()), CoreMatchers.is(KeyType.RSA3072));

    MatcherAssert.assertThat(
        KeyType.fromKey(rsa4096.getPrivate()), CoreMatchers.is(KeyType.RSA4096));
    MatcherAssert.assertThat(
        KeyType.fromKey(rsa4096.getPublic()), CoreMatchers.is(KeyType.RSA4096));
  }

  @Test
  public void testFromValueAcceptsBytesAndUnsignedValues() {
    for (KeyType keyType : KeyType.values()) {
      MatcherAssert.assertThat(KeyType.fromValue(keyType.value), CoreMatchers.is(keyType));
      MatcherAssert.assertThat(KeyType.fromValue(keyType.value & 0xFF), CoreMatchers.is(keyType));
    }
    MatcherAssert.assertThat(KeyType.fromValue(0xE0), CoreMatchers.is(KeyType.ED25519));
    MatcherAssert.assertThat(KeyType.fromValue(0xE1), CoreMatchers.is(KeyType.X25519));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testFromValueRejectsUnknownValues() {
    KeyType.fromValue(0xE8);
  }

  @Test
  public void testPostQuantumFromValue() {
    MatcherAssert.assertThat(KeyType.fromValue(0xE2), CoreMatchers.is(KeyType.MLDSA44));
    MatcherAssert.assertThat(KeyType.fromValue(0xE3), CoreMatchers.is(KeyType.MLDSA65));
    MatcherAssert.assertThat(KeyType.fromValue(0xE4), CoreMatchers.is(KeyType.MLDSA87));
    MatcherAssert.assertThat(KeyType.fromValue(0xE5), CoreMatchers.is(KeyType.MLKEM512));
    MatcherAssert.assertThat(KeyType.fromValue(0xE6), CoreMatchers.is(KeyType.MLKEM768));
    MatcherAssert.assertThat(KeyType.fromValue(0xE7), CoreMatchers.is(KeyType.MLKEM1024));
  }

  @Test
  public void testPostQuantumParams() {
    for (KeyType keyType : PostQuantumTestKeys.ML_DSA_KEY_TYPES) {
      MatcherAssert.assertThat(keyType.params.algorithm, CoreMatchers.is(KeyType.Algorithm.MLDSA));
    }
    for (KeyType keyType : PostQuantumTestKeys.ML_KEM_KEY_TYPES) {
      MatcherAssert.assertThat(keyType.params.algorithm, CoreMatchers.is(KeyType.Algorithm.MLKEM));
    }
  }

  @Test
  public void testFromPostQuantumKeys() {
    for (KeyType expected :
        Arrays.asList(
            KeyType.MLDSA44,
            KeyType.MLDSA65,
            KeyType.MLDSA87,
            KeyType.MLKEM512,
            KeyType.MLKEM768,
            KeyType.MLKEM1024)) {
      PublicKey pub =
          PostQuantumTestKeys.publicKey(
              expected, PostQuantumTestKeys.publicKeyBytes(expected, 0x42));
      MatcherAssert.assertThat(KeyType.fromKey(pub), CoreMatchers.is(expected));

      byte[] seed = new byte[PostQuantumTestKeys.seedLength(expected)];
      Arrays.fill(seed, (byte) 0x11);
      PrivateKey priv = PostQuantumTestKeys.privateKey(expected, seed);
      MatcherAssert.assertThat(KeyType.fromKey(priv), CoreMatchers.is(expected));
      PrivateKeyValues values = PrivateKeyValues.fromPrivateKey(priv);
      MatcherAssert.assertThat(KeyType.fromKeyParams(values), CoreMatchers.is(expected));
    }
  }
}

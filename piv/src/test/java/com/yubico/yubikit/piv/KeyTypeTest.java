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
package com.yubico.yubikit.piv;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

public class KeyTypeTest {
    private static KeyPair secp256r1;
    private static KeyPair secp384r1;
    private static KeyPair secp256k1;
    private static KeyPair secp521r1;
    private static KeyPair rsa1024;
    private static KeyPair rsa2048;
    private static KeyPair rsa4096;

    @BeforeClass
    public static void setupKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyType.Algorithm.EC.name());
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        secp256r1 = kpg.generateKeyPair();
        kpg.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        secp256k1 = kpg.generateKeyPair();
        kpg.initialize(new ECGenParameterSpec("secp384r1"), new SecureRandom());
        secp384r1 = kpg.generateKeyPair();
        kpg.initialize(new ECGenParameterSpec("secp521r1"), new SecureRandom());
        secp521r1 = kpg.generateKeyPair();

        kpg = KeyPairGenerator.getInstance(KeyType.Algorithm.RSA.name());
        kpg.initialize(1024);
        rsa1024 = kpg.generateKeyPair();
        kpg.initialize(2048);
        rsa2048 = kpg.generateKeyPair();
        kpg.initialize(4096);
        rsa4096 = kpg.generateKeyPair();
    }

    @Test
    public void testFromEcKey() {
        MatcherAssert.assertThat(KeyType.fromKey(secp256r1.getPrivate()), CoreMatchers.is(KeyType.ECCP256));
        MatcherAssert.assertThat(KeyType.fromKey(secp256r1.getPublic()), CoreMatchers.is(KeyType.ECCP256));

        MatcherAssert.assertThat(KeyType.fromKey(secp384r1.getPrivate()), CoreMatchers.is(KeyType.ECCP384));
        MatcherAssert.assertThat(KeyType.fromKey(secp384r1.getPublic()), CoreMatchers.is(KeyType.ECCP384));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testP256K1Public() {
        KeyType.fromKey(secp256k1.getPublic());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testP256K1Private() {
        KeyType.fromKey(secp256k1.getPrivate());
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
        MatcherAssert.assertThat(KeyType.fromKey(rsa1024.getPrivate()), CoreMatchers.is(KeyType.RSA1024));
        MatcherAssert.assertThat(KeyType.fromKey(rsa1024.getPublic()), CoreMatchers.is(KeyType.RSA1024));

        MatcherAssert.assertThat(KeyType.fromKey(rsa2048.getPrivate()), CoreMatchers.is(KeyType.RSA2048));
        MatcherAssert.assertThat(KeyType.fromKey(rsa2048.getPublic()), CoreMatchers.is(KeyType.RSA2048));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRsa4096Public() {
        KeyType.fromKey(rsa4096.getPublic());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRsa4096Private() {
        KeyType.fromKey(rsa4096.getPrivate());
    }
}

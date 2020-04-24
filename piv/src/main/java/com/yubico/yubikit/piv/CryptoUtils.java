/*
 * Copyright (C) 2019 Yubico.
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

import android.annotation.SuppressLint;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

class CryptoUtils {
    private static final byte[] P256_PREFIX = new byte[]{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};
    private static final byte[] P384_PREFIX = new byte[]{0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, (byte) 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00};

    /**
     * Generates a public ECC key object from the provided key specification
     * @param curve curve Supported curves: P-256 and P-384
     * @param encoded key data
     * @return public key
     * @throws NoSuchAlgorithmException no ECC algorithm found
     * @throws InvalidKeySpecException provided data is inappropriate
     */
    static PublicKey publicEccKey(Curve curve, byte[] encoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(Algorithm.EC.value);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(curve.prefix, 0, curve.prefix.length);
        stream.write(encoded, 0, encoded.length);
        return keyFactory.generatePublic(new X509EncodedKeySpec(stream.toByteArray()));
    }

    /**
     * Generates a public RSA key object from the provided key specification
     * @param modulus the modulus
     * @param publicExponent the public exponent
     * @return public key
     * @throws NoSuchAlgorithmException no RSA algorithm found
     * @throws InvalidKeySpecException provided data is inappropriate
     */
    static PublicKey publicRsaKey(BigInteger modulus, BigInteger publicExponent) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance(Algorithm.RSA.value);
        return factory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
    }

    /**
     * Decrypt cypher using provided key
     * @param key the key for symmetric encryption
     * @param cypherText encrypted text
     * @return decrypted text
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    static byte[] decryptDESede(Key key, byte[] cypherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        @SuppressLint("GetInstance") Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cypherText);
    }

    /**
     * Encrypt text with provided key
     * @param key the key for symmetric encryption
     * @param text text for encryption
     * @return encrypted text
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    static byte[] encryptDESede(Key key, byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        @SuppressLint("GetInstance") Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(text);
    }

    enum Algorithm {
        RSA("RSA"),
        EC("EC");

        private String value;
        Algorithm(String value) {
            this.value = value;
        }
    }

    enum Curve {
        P256(P256_PREFIX),
        P384(P384_PREFIX);

        private byte[] prefix;
        Curve(byte[] prefix) {
            this.prefix = prefix;
        }
    }

}

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

package com.yubico.yubikit.core.keys;

import static com.yubico.yubikit.core.internal.PrivateKeyUtils.bytesToLength;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public abstract class PublicKeyValues {
    final int bitLength;

    protected PublicKeyValues(int bitLength) {
        this.bitLength = bitLength;
    }

    public final int getBitLength() {
        return bitLength;
    }

    public abstract byte[] getEncoded();

    public final EncodedKeySpec toKeySpec() {
        return new X509EncodedKeySpec(getEncoded());
    }

    public abstract PublicKey toPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException;

    public static class Ec extends PublicKeyValues {
        private final EllipticCurveValues ellipticCurveValues;
        private final BigInteger x;
        private final BigInteger y;

        public Ec(EllipticCurveValues ellipticCurveValues, BigInteger x, BigInteger y) {
            super(ellipticCurveValues.getBitLength());
            this.ellipticCurveValues = ellipticCurveValues;
            this.x = x;
            this.y = y;
        }

        public EllipticCurveValues getCurveParams() {
            return ellipticCurveValues;
        }

        public BigInteger getX() {
            return x;
        }

        public BigInteger getY() {
            return y;
        }

        @Override
        public byte[] getEncoded() {
            //TODO: Handle Curve 25519
            byte[] prefix = ellipticCurveValues.getAsn1Prefix();
            int coordSize = (int) Math.ceil(ellipticCurveValues.getBitLength() / 8.0);
            return ByteBuffer.allocate(prefix.length + 1 + 2 * coordSize)
                    .put(prefix)
                    .put((byte) 0x04)
                    .put(bytesToLength(getX(), coordSize))
                    .put(bytesToLength(getY(), coordSize))
                    .array();
        }

        @Override
        public PublicKey toPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
            //TODO: Handle Curve 25519
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePublic(new X509EncodedKeySpec(getEncoded()));
        }
    }

    public static class Rsa extends PublicKeyValues {
        private final BigInteger modulus;
        private final BigInteger publicExponent;

        public Rsa(BigInteger modulus, BigInteger publicExponent) {
            super(modulus.bitLength());
            this.modulus = modulus;
            this.publicExponent = publicExponent;
        }

        public BigInteger getModulus() {
            return modulus;
        }

        public BigInteger getPublicExponent() {
            return publicExponent;
        }

        @Override
        public byte[] getEncoded() {
            // TODO: Don't use toPublicKey()
            try {
                return toPublicKey().getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public PublicKey toPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        }
    }
}

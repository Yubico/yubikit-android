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

import static com.yubico.yubikit.core.util.ByteUtils.intToLength;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Values defining a public key, such as an RSA or EC key.
 */
public abstract class PublicKeyValues {
    private static final byte[] OID_ECDSA = new byte[]{0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01};
    private static final byte[] OID_RSA_ENCRYPTION = new byte[]{0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01};

    protected final int bitLength;

    protected PublicKeyValues(int bitLength) {
        this.bitLength = bitLength;
    }

    public final int getBitLength() {
        return bitLength;
    }

    public abstract byte[] getEncoded();

    /**
     * Instantiates a JCA PublicKey using the contained parameters.
     * This requires a SecurityProvider capable of handling the key type.
     *
     * @return a public key, usable for cryptographic operations
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public abstract PublicKey toPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException;

    public static PublicKeyValues fromPublicKey(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey) {
            return new Rsa(((RSAPublicKey) publicKey).getModulus(), ((RSAPublicKey) publicKey).getPublicExponent());
        }
        byte[] encoded = publicKey.getEncoded();
        try {
            Map<Integer, byte[]> tlvs = Tlvs.decodeMap(Tlvs.unpackValue(0x30, encoded));
            List<Tlv> sequence = Tlvs.decodeList(tlvs.get(0x30));
            byte[] algorithm = sequence.get(0).getValue();
            byte[] bitString = tlvs.get(0x03);
            byte[] encodedKey = Arrays.copyOfRange(bitString, 1, bitString.length);
            if (Arrays.equals(OID_ECDSA, algorithm)) {
                byte[] parameter = sequence.get(1).getValue();
                EllipticCurveValues curve = EllipticCurveValues.fromOid(parameter);
                return Ec.fromEncodedPoint(curve, encodedKey);
            } else {
                for (EllipticCurveValues curve : Arrays.asList(EllipticCurveValues.Ed25519, EllipticCurveValues.X25519)) {
                    if (Arrays.equals(curve.getOid(), algorithm)) {
                        return new Cv25519(curve, encodedKey);
                    }
                }
            }
        } catch (BadResponseException e) {
            throw new RuntimeException(e);
        }

        throw new IllegalStateException();
    }

    public static class Cv25519 extends PublicKeyValues {
        private final EllipticCurveValues ellipticCurveValues;
        private final byte[] bytes;

        public Cv25519(EllipticCurveValues ellipticCurveValues, byte[] bytes) {
            super(ellipticCurveValues.getBitLength());
            if (!(ellipticCurveValues == EllipticCurveValues.Ed25519 || ellipticCurveValues == EllipticCurveValues.X25519)) {
                throw new IllegalArgumentException("InvalidCurve");
            }
            this.ellipticCurveValues = ellipticCurveValues;
            this.bytes = Arrays.copyOf(bytes, bytes.length);
        }

        public EllipticCurveValues getCurveParams() {
            return ellipticCurveValues;
        }

        public byte[] getBytes() {
            return Arrays.copyOf(bytes, bytes.length);
        }

        @Override
        public byte[] getEncoded() {
            return new Tlv(0x30, Tlvs.encodeList(Arrays.asList(
                    new Tlv(0x30, new Tlv(0x06, ellipticCurveValues.getOid()).getBytes()),
                    new Tlv(0x03, ByteBuffer.allocate(1 + bytes.length).put((byte) 0).put(bytes).array())
            ))).getBytes();
        }

        @Override
        public PublicKey toPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory keyFactory = KeyFactory.getInstance(ellipticCurveValues.name());
            return keyFactory.generatePublic(new X509EncodedKeySpec(getEncoded()));
        }

        @Override
        public String toString() {
            return "PublicKeyValues.Cv25519{" +
                    "curve=" + ellipticCurveValues.name() +
                    ", publicKey=" + StringUtils.bytesToHex(bytes) +
                    ", bitLength=" + bitLength +
                    '}';
        }
    }

    public static class Ec extends PublicKeyValues {
        private final EllipticCurveValues ellipticCurveValues;
        private final BigInteger x;
        private final BigInteger y;

        public Ec(EllipticCurveValues ellipticCurveValues, BigInteger x, BigInteger y) {
            super(ellipticCurveValues.getBitLength());
            if (ellipticCurveValues == EllipticCurveValues.Ed25519 || ellipticCurveValues == EllipticCurveValues.X25519) {
                throw new IllegalArgumentException("InvalidCurve");
            }
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

        public byte[] getEncodedPoint() {
            int coordSize = (int) Math.ceil(ellipticCurveValues.getBitLength() / 8.0);
            return ByteBuffer.allocate(1 + 2 * coordSize)
                    .put((byte) 0x04)
                    .put(intToLength(x, coordSize))
                    .put(intToLength(y, coordSize))
                    .array();
        }

        @Override
        public byte[] getEncoded() {
            byte[] encodedPoint = getEncodedPoint();
            return new Tlv(0x30, Tlvs.encodeList(Arrays.asList(
                    new Tlv(0x30, Tlvs.encodeList(Arrays.asList(
                            new Tlv(0x06, OID_ECDSA),
                            new Tlv(0x06, ellipticCurveValues.getOid())
                    ))),
                    new Tlv(0x03, ByteBuffer.allocate(1 + encodedPoint.length).put((byte) 0).put(encodedPoint).array())
            ))).getBytes();
        }

        @Override
        public ECPublicKey toPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(getEncoded()));
        }

        @Override
        public String toString() {
            return "PublicKeyValues.Ec{" +
                    "curve=" + ellipticCurveValues.name() +
                    ", x=" + x +
                    ", y=" + y +
                    ", bitLength=" + bitLength +
                    '}';
        }

        public static Ec fromEncodedPoint(EllipticCurveValues curve, byte[] encoded) {
            ByteBuffer buf = ByteBuffer.wrap(encoded);
            if (buf.get() != 0x04) {
                throw new IllegalArgumentException("Only uncompressed public keys are supported");
            }
            byte[] coordBuf = new byte[(encoded.length - 1) / 2];
            buf.get(coordBuf);
            BigInteger x = new BigInteger(1, coordBuf);
            buf.get(coordBuf);
            BigInteger y = new BigInteger(1, coordBuf);
            return new Ec(curve, x, y);
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
            byte[] bitstring = new Tlv(0x30, Tlvs.encodeList(Arrays.asList(
                    new Tlv(0x02, modulus.toByteArray()),
                    new Tlv(0x02, publicExponent.toByteArray())
            ))).getBytes();
            return new Tlv(0x30, Tlvs.encodeList(Arrays.asList(
                    new Tlv(0x30, Tlvs.encodeList(Arrays.asList(
                            new Tlv(0x06, OID_RSA_ENCRYPTION),
                            new Tlv(0x05, new byte[0])
                    ))),
                    new Tlv(0x03, ByteBuffer
                            .allocate(1 + bitstring.length)
                            .put((byte) 0)
                            .put(bitstring)
                            .array()
                    )
            ))).getBytes();
        }

        @Override
        public RSAPublicKey toPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) factory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        }

        @Override
        public String toString() {
            return "PublicKeyValues.Rsa{" +
                    "modulus=" + modulus +
                    ", publicExponent=" + publicExponent +
                    ", bitLength=" + bitLength +
                    '}';
        }
    }
}

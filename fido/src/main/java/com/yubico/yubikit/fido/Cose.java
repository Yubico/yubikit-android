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

package com.yubico.yubikit.fido;

import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.internal.codec.Base64;

import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nullable;

public class Cose {
    /**
     * OID 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
     */
    private static final byte[] EC_PUBLIC_KEY_OID = {(byte) 0x2A, -122, 0x48, -50, 0x3D, 0x02, 0x01};

    /**
     * OID 1.2.840.10045.3.1.7
     */
    private static final byte[] P256_CURVE_OID = {(byte) 0x2A, -122, 0x48, -50, 0x3D, 0x03, 0x01, 7};

    /**
     * OID 1.3.132.0.34
     */
    private static final byte[] P384_CURVE_OID = {(byte) 0x2B, -127, 0x04, 0, 34};

    /**
     * OID 1.3.132.0.35
     */
    private static final byte[] P512_CURVE_OID = {(byte) 0x2B, -127, 0x04, 0, 35};

    private static final byte[] ED25519_CURVE_OID = {(byte) 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70};

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Cose.class);

    public static Integer getAlgorithm(Map<Integer, ?> cosePublicKey) {
        Integer alg = (Integer) Objects.requireNonNull(cosePublicKey.get(3));
        Logger.debug(logger, "alg: {}", alg);
        return (int) alg;
    }

    @Nullable
    public static PublicKey getPublicKey(@Nullable Map<Integer, ?> cosePublicKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException {

        if (cosePublicKey == null) {
            return null;
        }

        final Integer kty = (Integer) Objects.requireNonNull(cosePublicKey.get(1));
        Logger.debug(logger, "kty: {}", kty);
        PublicKey publicKey;
        switch (kty) {
            case 1:
                publicKey = importCoseEdDsaPublicKey(cosePublicKey);
                break;
            case 2:
                publicKey = importCoseEcdsaPublicKey(cosePublicKey);
                break;
            case 3:
                publicKey = importCoseRsaPublicKey(cosePublicKey);
                break;
            default:
                throw new IllegalArgumentException("Unsupported key type: " + kty);
        }

        Logger.debug(logger, "publicKey: {}", Base64.encode(publicKey.getEncoded()));

        return publicKey;
    }

    private static PublicKey importCoseEdDsaPublicKey(Map<Integer, ?> cosePublicKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        final Integer crv = (Integer) Objects.requireNonNull(cosePublicKey.get(-1));
        Logger.debug(logger, "crv: {}", crv);
        if (crv == 6) {
            return importCoseEd25519PublicKey(cosePublicKey);
        }
        throw new IllegalArgumentException("Unsupported EdDSA curve: " + crv);
    }

    private static PublicKey importCoseEd25519PublicKey(Map<Integer, ?> cosePublicKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        final byte[] rawKey = (byte[]) Objects.requireNonNull(cosePublicKey.get(-2));
        Logger.debug(logger, "raw: {}", Base64.encode(rawKey));
        final byte[] x509Key = encodeDerSequence(
                ED25519_CURVE_OID,
                encodeDerBitStringWithZeroUnused(rawKey)
        );

        KeyFactory kFact = KeyFactory.getInstance("EdDSA");
        return kFact.generatePublic(new X509EncodedKeySpec(x509Key));
    }

    private static PublicKey importCoseEcdsaPublicKey(Map<Integer, ?> cosePublicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final Integer crv = (Integer) Objects.requireNonNull(cosePublicKey.get(-1));
        final byte[] x = (byte[]) Objects.requireNonNull(cosePublicKey.get(-2));
        final byte[] y = (byte[]) Objects.requireNonNull(cosePublicKey.get(-3));

        Logger.debug(logger, "crv: {}", crv);
        Logger.debug(logger, "x: {}", Base64.encode(x));
        Logger.debug(logger, "y: {}", Base64.encode(y));

        final byte[] curveOid;
        switch (crv) {
            case 1:
                curveOid = P256_CURVE_OID;
                break;

            case 2:
                curveOid = P384_CURVE_OID;
                break;

            case 3:
                curveOid = P512_CURVE_OID;
                break;

            default:
                throw new IllegalArgumentException("Unknown COSE EC2 curve: " + crv);
        }

        final byte[] algId = encodeDerSequence(
                encodeDerObjectId(EC_PUBLIC_KEY_OID),
                encodeDerObjectId(curveOid)
        );

        final byte[] derBitString = ByteBuffer.allocate(1 + x.length + y.length)
                .put(new byte[]{0x04})
                .put(x)
                .put(y)
                .array();

        final byte[] rawKey = encodeDerBitStringWithZeroUnused(derBitString);
        final byte[] x509Key = encodeDerSequence(algId, rawKey);

        KeyFactory kFact = KeyFactory.getInstance("EC");
        return kFact.generatePublic(new X509EncodedKeySpec(x509Key));
    }

    private static PublicKey importCoseRsaPublicKey(Map<Integer, ?> cosePublicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] n = (byte[]) Objects.requireNonNull(cosePublicKey.get(-1));
        byte[] e = (byte[]) Objects.requireNonNull(cosePublicKey.get(-2));
        Logger.debug(logger, "n: {}", Base64.encode(n));
        Logger.debug(logger, "e: {}", Base64.encode(e));
        RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, n), new BigInteger(1, e));
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static byte[] encodeDerObjectId(final byte[] oid) {
        return ByteBuffer.allocate(2 + oid.length)
                .put((byte) 0x06)
                .put((byte) oid.length)
                .put(oid)
                .array();
    }

    private static byte[] encodeDerSequence(final byte[]... items) {
        byte[] content;

        if (items.length == 0) {
            content = new byte[0];
        } else {
            int contentLength = 0;
            for (byte[] item : items) {
                contentLength += item.length;
            }

            ByteBuffer contentBuffer = ByteBuffer.allocate(contentLength);
            for (byte[] item : items) {
                contentBuffer.put(item);
            }
            content = contentBuffer.array();
        }

        byte[] encodedDerLength = encodeDerLength(content.length);

        return ByteBuffer.allocate(1 + encodedDerLength.length + content.length)
                .put((byte) 0x30)
                .put(encodedDerLength)
                .put(content)
                .array();
    }

    private static byte[] encodeDerLength(final int length) {
        if (length <= 127) {
            return new byte[]{(byte) length};
        } else if (length <= 0xffff) {
            if (length <= 255) {
                return new byte[]{-127, (byte) length};
            } else {
                return new byte[]{-126, (byte) (length >> 8), (byte) (length % 0x0100)};
            }
        } else {
            throw new UnsupportedOperationException("Too long: " + length);
        }
    }

    private static byte[] encodeDerBitStringWithZeroUnused(final byte[] content) {
        byte[] encodedDerLength = encodeDerLength(1 + content.length);
        return ByteBuffer.allocate(1 + encodedDerLength.length + 1 + content.length)
                .put((byte) 0x03)
                .put(encodedDerLength)
                .put(new byte[]{0})
                .put(content)
                .array();
    }
}

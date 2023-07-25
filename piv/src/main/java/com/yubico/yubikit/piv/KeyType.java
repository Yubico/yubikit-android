/*
 * Copyright (C) 2019-2022 Yubico.
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

import com.yubico.yubikit.core.internal.CurveParams;

import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import javax.annotation.Nonnull;

/**
 * Supported private key types for use with the PIV YubiKey application.
 */
public enum KeyType {
    /**
     * RSA with a 1024 bit key.
     */
    RSA1024((byte) 0x06, new RsaKeyParams(1024)),
    /**
     * RSA with a 2048 bit key.
     */
    RSA2048((byte) 0x07, new RsaKeyParams(2048)),
    /**
     * Elliptic Curve key, using NIST Curve P-256.
     */
    ECCP256((byte) 0x11, new EcKeyParams(CurveParams.SECP256R1)),
    /**
     * Elliptic Curve key, using NIST Curve P-384.
     */
    ECCP384((byte) 0x14, new EcKeyParams(CurveParams.SECP384R1));

    public final byte value;
    public final KeyParams params;

    KeyType(byte value, KeyParams params) {
        this.value = value;
        this.params = params;
    }

    /**
     * Returns the key type corresponding to the given PIV algorithm constant.
     */
    public static KeyType fromValue(int value) {
        for (KeyType type : KeyType.values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Not a valid KeyType:" + value);
    }

    /**
     * Returns the key type corresponding to the given key.
     */
    public static KeyType fromKey(Key key) {
        for (KeyType keyType : values()) {
            if (keyType.params.matches(key)) {
                return keyType;
            }
        }
        throw new IllegalArgumentException("Unsupported key type");
    }

    /**
     * Key algorithm identifier.
     */
    public enum Algorithm {
        RSA, EC
    }

    /**
     * Algorithm parameters used by a KeyType.
     */
    public static abstract class KeyParams {
        @Nonnull  // Needed for Kotlin to use when() on algorithm and not have to null check.
        public final Algorithm algorithm;
        public final int bitLength;

        private KeyParams(Algorithm algorithm, int bitLength) {
            this.algorithm = algorithm;
            this.bitLength = bitLength;
        }

        protected abstract boolean matches(Key key);
    }

    /**
     * Algorithm parameters for RSA keys.
     */
    public static final class RsaKeyParams extends KeyParams {
        private RsaKeyParams(int bitLength) {
            super(Algorithm.RSA, bitLength);
        }

        @Override
        protected boolean matches(Key key) {
            if (key instanceof RSAKey) {
                return ((RSAKey) key).getModulus().bitLength() == bitLength;
            }
            return false;
        }
    }

    /**
     * Algorithm parameters for EC keys.
     */
    public static final class EcKeyParams extends KeyParams {
        private final CurveParams curveParams;

        private EcKeyParams(CurveParams curveParams) {
            super(Algorithm.EC, curveParams.getBitLength());
            this.curveParams = curveParams;
        }

        byte[] getPrefix() {
            return curveParams.getPrefix();
        }

        @Override
        protected boolean matches(Key key) {
            return key instanceof ECKey && curveParams.matchesKey((ECKey) key);
        }
    }
}

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

import com.yubico.yubikit.core.util.StringUtils;

import java.util.Arrays;

public enum EllipticCurveValues {
    SECP256R1(
            256,
            new byte[]{0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07}
    ),
    SECP256K1(
            256,
            new byte[]{0x2b, (byte) 0x81, 0x04, 0x00, 0x0a}
    ),
    SECP384R1(
            384,
            new byte[]{0x2b, (byte) 0x81, 0x04, 0x00, 0x22}
    ),
    SECP521R1(521,
            new byte[]{0x2b, (byte) 0x81, 0x04, 0x00, 0x23}
    ),
    BrainpoolP256R1(
            256,
            new byte[]{0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07}
    ),
    BrainpoolP384R1(
            384,
            new byte[]{0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b}
    ),
    BrainpoolP512R1(
            512,
            new byte[]{0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d}
    ),
    X25519(
            256,
            new byte[]{0x2b, 0x65, 0x6e}
    ),
    Ed25519(
            256,
            new byte[]{0x2b, 0x65, 0x70}
    );

    private final int bitLength;
    private final byte[] oid;

    EllipticCurveValues(int bitLength, byte[] oid) {
        this.bitLength = bitLength;
        this.oid = oid;
    }

    public int getBitLength() {
        return bitLength;
    }

    byte[] getOid() {
        return Arrays.copyOf(oid, oid.length);
    }

    @Override
    public String toString() {
        return "EllipticCurveValues{" +
                "name=" + name() +
                ", bitLength=" + bitLength +
                ", oid=" + StringUtils.bytesToHex(oid) +
                '}';
    }

    public static EllipticCurveValues fromOid(byte[] oid) {
        for (EllipticCurveValues match : EllipticCurveValues.values()) {
            if (Arrays.equals(oid, match.oid)) {
                return match;
            }
        }
        throw new IllegalArgumentException("Not a supported EllipticCurve");
    }
}

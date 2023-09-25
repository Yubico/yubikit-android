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

package com.yubico.yubikit.openpgp;

import com.yubico.yubikit.core.keys.EllipticCurveValues;

import java.util.Arrays;

public enum OpenPgpCurve {
    SECP256R1(EllipticCurveValues.SECP256R1, new byte[]{0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07}),
    SECP256K1(EllipticCurveValues.SECP256K1, new byte[]{0x2b, (byte) 0x81, 0x04, 0x00, 0x0a}),
    SECP384R1(EllipticCurveValues.SECP384R1, new byte[]{0x2b, (byte) 0x81, 0x04, 0x00, 0x22}),
    SECP521R1(EllipticCurveValues.SECP521R1, new byte[]{0x2b, (byte) 0x81, 0x04, 0x00, 0x23}),
    BrainpoolP256R1(EllipticCurveValues.BrainpoolP256R1, new byte[]{0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07}),
    BrainpoolP384R1(EllipticCurveValues.BrainpoolP384R1, new byte[]{0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b}),
    BrainpoolP512R1(EllipticCurveValues.BrainpoolP512R1, new byte[]{0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d}),
    X25519(EllipticCurveValues.X25519, new byte[]{0x2b, 0x06, 0x01, 0x04, 0x01, (byte) 0x97, 0x55, 0x01, 0x05, 0x01}),
    Ed25519(EllipticCurveValues.Ed25519, new byte[]{0x2b, 0x06, 0x01, 0x04, 0x01, (byte) 0xda, 0x47, 0x0f, 0x01});

    private final EllipticCurveValues ellipticCurveValues;
    private final byte[] oid;

    OpenPgpCurve(EllipticCurveValues ellipticCurveValues, byte[] oid) {
        this.ellipticCurveValues = ellipticCurveValues;
        this.oid = oid;
    }

    byte[] getOid() {
        return Arrays.copyOf(oid, oid.length);
    }

    EllipticCurveValues getValues() {
        return ellipticCurveValues;
    }

    static OpenPgpCurve fromOid(byte[] oid) {
        for (OpenPgpCurve params : OpenPgpCurve.values()) {
            // Allow given oid to have trailing zeroes.
            byte[] compareOid = Arrays.copyOf(params.oid, Math.max(params.oid.length, oid.length));
            if (Arrays.equals(compareOid, oid)) {
                return params;
            }
        }
        throw new IllegalArgumentException("Not a supported curve OID");
    }
}

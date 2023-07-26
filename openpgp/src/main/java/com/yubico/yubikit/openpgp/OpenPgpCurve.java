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

public enum OpenPgpCurve {
    SECP256R1(EllipticCurveValues.SECP256R1),
    SECP256K1(EllipticCurveValues.SECP256K1),
    SECP384R1(EllipticCurveValues.SECP384R1),
    SECP521R1(EllipticCurveValues.SECP521R1),
    BrainpoolP256R1(EllipticCurveValues.BrainpoolP256R1),
    BrainpoolP384R1(EllipticCurveValues.BrainpoolP384R1),
    BrainpoolP512R1(EllipticCurveValues.BrainpoolP512R1),
    X25519(EllipticCurveValues.X25519),
    Ed25519(EllipticCurveValues.Ed25519);

    private final EllipticCurveValues ellipticCurveValues;

    OpenPgpCurve(EllipticCurveValues ellipticCurveValues) {
        this.ellipticCurveValues = ellipticCurveValues;
    }

    EllipticCurveValues getValues() {
        return ellipticCurveValues;
    }
}

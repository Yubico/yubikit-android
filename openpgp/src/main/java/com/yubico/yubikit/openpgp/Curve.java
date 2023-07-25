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

import com.yubico.yubikit.core.internal.CurveParams;

public enum Curve {
    SECP256R1(CurveParams.SECP256R1),
    SECP256K1(CurveParams.SECP256K1),
    SECP384R1(CurveParams.SECP384R1),
    SECP521R1(CurveParams.SECP521R1),
    BrainpoolP256R1(CurveParams.BrainpoolP256R1),
    BrainpoolP384R1(CurveParams.BrainpoolP384R1),
    BrainpoolP512R1(CurveParams.BrainpoolP512R1),
    X25519(CurveParams.X25519),
    Ed25519(CurveParams.Ed25519);

    private final CurveParams curveParams;

    Curve(CurveParams curveParams) {
        this.curveParams = curveParams;
    }

    CurveParams getParams() {
        return curveParams;
    }
}

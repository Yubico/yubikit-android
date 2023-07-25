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

package com.yubico.yubikit.core.internal;

/**
 * Used internally in YubiKit, don't use from applications.
 */
public class RsaPrivateNumbers {
    private final byte[] modulus;
    private final byte[] publicExponent;
    private final byte[] primeP;
    private final byte[] primeQ;
    private final byte[] primeExponentP;
    private final byte[] primeExponentQ;
    private final byte[] crtCoefficient;

    public RsaPrivateNumbers(byte[] modulus, byte[] publicExponent, byte[] primeP, byte[] primeQ, byte[] primeExponentP, byte[] primeExponentQ, byte[] crtCoefficient) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.primeP = primeP;
        this.primeQ = primeQ;
        this.primeExponentP = primeExponentP;
        this.primeExponentQ = primeExponentQ;
        this.crtCoefficient = crtCoefficient;
    }

    public byte[] getModulus() {
        return modulus;
    }

    public byte[] getPublicExponent() {
        return publicExponent;
    }

    public byte[] getPrimeP() {
        return primeP;
    }

    public byte[] getPrimeQ() {
        return primeQ;
    }

    public byte[] getPrimeExponentP() {
        return primeExponentP;
    }

    public byte[] getPrimeExponentQ() {
        return primeExponentQ;
    }

    public byte[] getCrtCoefficient() {
        return crtCoefficient;
    }
}

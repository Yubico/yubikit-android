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

import java.util.Arrays;

public enum KeyRef {
    SIG((byte) 0x01, Do.ALGORITHM_ATTRIBUTES_SIG, Do.UIF_SIG, Do.FINGERPRINT_SIG, Do.GENERATION_TIME_SIG, Crt.SIG),
    DEC((byte) 0x02, Do.ALGORITHM_ATTRIBUTES_DEC, Do.UIF_DEC, Do.FINGERPRINT_DEC, Do.GENERATION_TIME_DEC, Crt.DEC),
    AUT((byte) 0x03, Do.ALGORITHM_ATTRIBUTES_AUT, Do.UIF_AUT, Do.FINGERPRINT_AUT, Do.GENERATION_TIME_AUT, Crt.AUT),
    ATT((byte) 0x81, Do.ALGORITHM_ATTRIBUTES_ATT, Do.UIF_ATT, Do.FINGERPRINT_ATT, Do.GENERATION_TIME_ATT, Crt.ATT);
    private final byte value;
    private final int algorithmAttributes;
    private final int uif;
    private final int fingerprint;
    private final int generationTime;
    private final byte[] crt;

    KeyRef(byte value, int algorithmAttributes, int uif, int fingerprint, int generationTime, byte[] crt) {
        this.value = value;
        this.algorithmAttributes = algorithmAttributes;
        this.uif = uif;
        this.fingerprint = fingerprint;
        this.generationTime = generationTime;
        this.crt = crt;
    }

    public byte getValue() {
        return value;
    }

    public int getAlgorithmAttributes() {
        return algorithmAttributes;
    }

    public int getUif() {
        return uif;
    }

    public int getFingerprint() {
        return fingerprint;
    }

    public int getGenerationTime() {
        return generationTime;
    }

    public byte[] getCrt() {
        return Arrays.copyOf(crt, crt.length);
    }

    static KeyRef fromValue(byte value) {
        for (KeyRef status : KeyRef.values()) {
            if (status.value == value) {
                return status;
            }
        }
        throw new IllegalArgumentException("Not a valid KeyRef:" + value);
    }
}

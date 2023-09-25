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

public enum ExtendedCapabilityFlag {
    KDF((byte) 1),
    PSO_DEC_ENC_AES((byte) (1 << 1)),
    ALGORITHM_ATTRIBUTES_CHANGEABLE((byte) (1 << 2)),
    PRIVATE_USE((byte) (1 << 3)),
    PW_STATUS_CHANGEABLE((byte) (1 << 4)),
    KEY_IMPORT((byte) (1 << 5)),
    GET_CHALLENGE((byte) (1 << 6)),
    SECURE_MESSAGING((byte) (1 << 7));

    public final byte value;

    ExtendedCapabilityFlag(byte value) {
        this.value = value;
    }
}

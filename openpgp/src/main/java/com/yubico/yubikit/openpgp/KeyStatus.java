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

public enum KeyStatus {
    NONE((byte) 0),
    GENERATED((byte) 1),
    IMPORTED((byte) 2);
    public final byte value;

    KeyStatus(byte value) {
        this.value = value;
    }

    static KeyStatus fromValue(byte value) {
        for (KeyStatus status : KeyStatus.values()) {
            if (status.value == value) {
                return status;
            }
        }
        throw new IllegalArgumentException("Not a valid KeyStatus:" + value);
    }
}
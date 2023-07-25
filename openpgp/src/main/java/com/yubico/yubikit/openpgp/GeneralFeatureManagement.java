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

public enum GeneralFeatureManagement {
    TOUCHSCREEN((byte)1),
    MICROPHONE((byte)(1 << 1)),
    LOUDSPEAKER((byte)(1 << 2)),
    LED((byte)(1 << 3)),
    KEYPAD((byte)(1 << 4)),
    BUTTON((byte)(1 << 5)),
    BIOMETRIC((byte)(1 << 6)),
    DISPLAY((byte)(1 << 7));

    public final byte value;

    GeneralFeatureManagement(byte value) {
        this.value = value;
    }
}

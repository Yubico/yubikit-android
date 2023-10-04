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

public enum Uif {
    OFF((byte) 0x00),
    ON((byte) 0x01),
    FIXED((byte) 0x02),
    CACHED((byte) 0x03),
    CACHED_FIXED((byte) 0x04);

    public final byte value;

    Uif(byte value) {
        this.value = value;
    }

    public boolean isFixed() {
        return this == Uif.FIXED || this == Uif.CACHED_FIXED;
    }

    public boolean isCached() {
        return this == Uif.CACHED || this == Uif.CACHED_FIXED;
    }

    @Override
    public String toString() {
        if (this == Uif.FIXED) {
            return "On (fixed)";
        }
        if (this == Uif.CACHED_FIXED) {
            return "Cached (fixed)";
        }

        String name = name();
        return name.charAt(0) + name.substring(1).toLowerCase();
    }

    public static Uif fromValue(byte value) {
        for (Uif type : Uif.values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Not a valid UIF:" + value);
    }

    public byte[] getBytes() {
        return new byte[]{value, GeneralFeatureManagement.BUTTON.value};
    }
}

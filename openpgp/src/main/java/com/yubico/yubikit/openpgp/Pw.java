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

public enum Pw {
    USER((byte) 0x81), RESET((byte) 0x82), ADMIN((byte) 0x83);
    public static final char[] DEFAULT_USER_PIN = "123456".toCharArray();
    public static final char[] DEFAULT_ADMIN_PIN = "12345678".toCharArray();

    private final byte value;

    Pw(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }
}

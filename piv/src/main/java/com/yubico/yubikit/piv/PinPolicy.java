/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.piv;

/**
 * PIN policy to be used for a key, valid for generate and import. Only available in YubiKey 4 and later.
 */
public enum PinPolicy {
    /**
     * The default behaviour for that key is used
     */
    DEFAULT(0x0),

    /**
     * PIN is never checked for operations
     */
    NEVER(0x1),

    /**
     * PIN is checked once for the session
     */
    ONCE(0x2),

    /**
     * PIN is verified just before operation
     */
    ALWAYS(0x3);

    public final int value;

    PinPolicy(int value) {
        this.value = value;
    }

    public static PinPolicy fromValue(int value) {
        for (PinPolicy type : PinPolicy.values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Not a valid PinPolicy :" + value);
    }
}

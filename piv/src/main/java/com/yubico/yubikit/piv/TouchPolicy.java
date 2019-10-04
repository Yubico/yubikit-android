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
 * Touch policy to be used for a key, valid for generate and import. Only available in YubiKey 4 and 5.
 */
public enum TouchPolicy {
    /**
     * The default behaviour for that key is used
     */
    DEFAULT(0x0),

    /**
     * Touch is never required for operations
     */
    NEVER(0x1),

    /**
     * Touch is always required for operations
     */
    ALWAYS(0x2),

    /**
     * Touch is cached for 15s after use (valid from 4.3).
     */
    CACHED(0x3);

    public final int value;

    TouchPolicy(int value) {
        this.value = value;
    }

    public static TouchPolicy fromValue(int value) {
        for (TouchPolicy type : TouchPolicy.values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Not a valid TouchPolicy :" + value);
    }

}

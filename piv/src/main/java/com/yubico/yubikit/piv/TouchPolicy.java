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
 * The touch policy of a private key defines whether or not a user presence check (physical touch) is required to use the key.
 * <p>
 * Setting a Touch policy other than DEFAULT requires YubiKey 4 or later.
 */
public enum TouchPolicy {
    /**
     * The default behavior for the particular key slot is used, which is always NEVER.
     */
    DEFAULT(0x0),

    /**
     * Touch is never required for using the key.
     */
    NEVER(0x1),

    /**
     * Touch is always required for using the key.
     */
    ALWAYS(0x2),

    /**
     * Touch is required, but cached for 15s after use, allowing multiple uses.
     * This setting requires YubiKey 4.3 or later.
     */
    CACHED(0x3);

    public final int value;

    TouchPolicy(int value) {
        this.value = value;
    }

    /**
     * Returns the touch policy corresponding to the given PIV application constant.
     */
    public static TouchPolicy fromValue(int value) {
        for (TouchPolicy type : TouchPolicy.values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Not a valid TouchPolicy :" + value);
    }

}

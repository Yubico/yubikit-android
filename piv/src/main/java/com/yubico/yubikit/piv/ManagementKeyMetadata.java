/*
 * Copyright (C) 2020 Yubico.
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
 * Metadata about the card management key.
 */
public class ManagementKeyMetadata {
    private final ManagementKeyType keyType;
    private final boolean defaultValue;
    private final TouchPolicy touchPolicy;

    public ManagementKeyMetadata(ManagementKeyType keyType, boolean defaultValue, TouchPolicy touchPolicy) {
        this.keyType = keyType;
        this.defaultValue = defaultValue;
        this.touchPolicy = touchPolicy;
    }

    /**
     * Get the algorithm of key used for the Management Key.
     *
     * @return a ManagementKeyType value
     */
    public ManagementKeyType getKeyType() {
        return keyType;
    }

    /**
     * Whether or not the default card management key is set. The key should be changed from the
     * default to prevent unwanted modification to the application.
     *
     * @return true if the default key is set.
     */
    public boolean isDefaultValue() {
        return defaultValue;
    }

    /**
     * Whether or not the YubiKey sensor needs to be touched when performing authentication.
     *
     * @return the touch policy of the card management key
     */
    public TouchPolicy getTouchPolicy() {
        return touchPolicy;
    }
}

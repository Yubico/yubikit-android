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
 * Metadata about the PIN or PUK.
 */
public class PinMetadata {
    private final boolean defaultValue;
    private final int totalAttempts;
    private final int attemptsRemaining;

    public PinMetadata(boolean defaultValue, int totalAttempts, int attemptsRemaining) {
        this.defaultValue = defaultValue;
        this.totalAttempts = totalAttempts;
        this.attemptsRemaining = attemptsRemaining;
    }

    /**
     * Whether or not the default PIN/PUK is set. The PIN/PUK should be changed from the default to
     * prevent unwanted usage of the application.
     *
     * @return true if the default key is set.
     */
    public boolean isDefaultValue() {
        return defaultValue;
    }

    /**
     * Returns the number of PIN/PUK attempts available after successful verification.
     */
    public int getTotalAttempts() {
        return totalAttempts;
    }

    /**
     * Returns the number of PIN/PUK attempts currently remaining.
     */
    public int getAttemptsRemaining() {
        return attemptsRemaining;
    }
}

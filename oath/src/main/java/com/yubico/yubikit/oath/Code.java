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

package com.yubico.yubikit.oath;


/**
 * Code generated on yubikey using OATH application
 */
public class Code {
    /**
     * one-time generated password
     */
    private final String value;

    /**
     * timestamp that was used to generate code
     */
    private final long validFrom;

    /**
     * timestamp when one-time password becomes invalid/expired
     */
    private final long validUntil;

    /**
     * Initiates instance of {@link Code}
     * @param value the value of one-time password received from key within CALCULATE or CALCULATE_ALL request
     * @param validFrom timestamp that was used to generate code
     * @param validUntil timestamp when one-time password becomes invalid/expired
     */
    public Code(String value, long validFrom, long validUntil) {
        this.value = value;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
    }

    /**
     * @return one-time generated password
     */
    public final String getValue() {
        return this.value;
    }

    /**
     * @return timestamp that was used to generate code
     */
    public final long getValidFrom() {
        return this.validFrom;
    }

    /**
     * @return timestamp when one-time password becomes invalid/expired
     */
    public final long getValidUntil() {
        return this.validUntil;
    }

    /**
     * Check if code is expired
     * @return true if it's still valid
     */
    public final boolean isValid() {
        return this.validUntil > System.currentTimeMillis();
    }

}

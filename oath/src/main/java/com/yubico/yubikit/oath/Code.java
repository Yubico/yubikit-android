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
 * A one-time OATH code, calculated from a Credential stored in a YubiKey.
 */
public class Code {
    private final String value;
    private final long validFrom;
    private final long validUntil;

    public Code(String value, long validFrom, long validUntil) {
        this.value = value;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
    }

    /**
     * Returns the String value, typically a 6-8 digit code.
     */
    public final String getValue() {
        return this.value;
    }

    /**
     * Returns a UNIX timestamp in ms for when the validity period starts.
     */
    public final long getValidFrom() {
        return this.validFrom;
    }

    /**
     * Returns a UNIX timestamp in ms for when the validity period ends.
     */
    public final long getValidUntil() {
        return this.validUntil;
    }
}

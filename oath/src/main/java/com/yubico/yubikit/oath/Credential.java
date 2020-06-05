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

import androidx.annotation.Nullable;

import java.io.Serializable;
import java.util.Arrays;

public class Credential implements Serializable {
    /**
     * Properties that identify credential
     */
    private final byte[] id;
    private final String name;
    private final int period;
    private final @Nullable String issuer;
    private final OathType oathType;

    /**
     * These properties are used to create credential on key
     * But can be unknown/not received from yubikey during enlisting or calculation
     */
    private boolean touchRequired = false;

    /**
     * Variation of code types:
     * 0x75 - TOTP full response
     * 0x76 - TOTP truncated response
     * 0x77 - HOTP
     * 0x7c - TOTP requires touch
     */
    private static final byte TYPE_HOTP = 0x77;
    private static final byte TYPE_TOUCH = 0x7c;

    /**
     * Construct a Credential using response data from a LIST call.
     * @param response The parsed response from the YubiKey.
     */
    Credential(OathApplication.ListResponse response) {
        id = response.id;
        oathType = response.oathType;

        CredentialIdUtils.CredentialIdData idData = CredentialIdUtils.parseId(id, oathType);
        issuer = idData.issuer;
        name = idData.name;
        period = idData.period;
    }

    /**
     * Construct a Credential using response data from a CALCULATE/CALCULATE_ALL call.
     * @param id The ID of the Credential
     * @param response The parsed response from the YubiKey for the Credential.
     */
    Credential(byte[] id, OathApplication.CalculateResponse response) {
        this.id = id;
        oathType = response.responseType == TYPE_HOTP ? OathType.HOTP : OathType.TOTP;
        touchRequired = response.responseType == TYPE_TOUCH;

        CredentialIdUtils.CredentialIdData idData = CredentialIdUtils.parseId(id, oathType);
        issuer = idData.issuer;
        name = idData.name;
        period = idData.period;
    }

    /**
     * Creates an instance of {@link Credential} from CredentialData successfully added to a YubiKey
     * @param credentialData the data used to create the Credential
     */
    Credential(CredentialData credentialData) {
        issuer = credentialData.getIssuer();
        name = credentialData.getName();
        oathType = credentialData.getOathType();
        period = credentialData.getPeriod();
        touchRequired = credentialData.isTouchRequired();
        id = credentialData.getId();
    }

    /**
     * Gets id of credential that used as unique identifier
     * @return period + issuer + name
     */
    public byte[] getId() {
        return id;
    }

    /**
     * Oath type {@link OathType}
     * @return HOTP or TOTP
     */
    public OathType getOathType() {
        return oathType;
    }

    /**
     * Name of credential issuer (e.g. Google, Amazon, Facebook, etc)
     * @return the issuer
     */
    @Nullable
    public String getIssuer() {
        return issuer;
    }

    /**
     * Name of the account (typically a username or email address)
     * @return the account name
     */
    public String getName() {
        return name;
    }

    /**
     * Period in seconds for how long code is valid from its calculation/generation time
     * @return the period (in seconds)
     */
    public int getPeriod() {
        return period;
    }

    /**
     * @return true if calculation requires touch on yubikey button
     */
    public boolean isTouchRequired() {
        return touchRequired;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Credential that = (Credential) o;
        return Arrays.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(id);
    }
}

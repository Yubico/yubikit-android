/*
 * Copyright (C) 2020-2023 Yubico.
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

package com.yubico.yubikit.fido.webauthn;

import javax.annotation.Nullable;

import java.util.HashMap;
import java.util.Map;

public class AuthenticatorSelectionCriteria {
    private static final String AUTHENTICATOR_ATTACHMENT = "authenticatorAttachment";
    private static final String RESIDENT_KEY = "residentKey";
    private static final String REQUIRE_RESIDENT_KEY = "requireResidentKey";
    private static final String USER_VERIFICATION = "userVerification";

    @Nullable
    private final AuthenticatorAttachment authenticatorAttachment;
    @Nullable
    private final ResidentKeyRequirement residentKey;
    private final boolean requireResidentKey;
    private final UserVerificationRequirement userVerification;

    public AuthenticatorSelectionCriteria(@Nullable AuthenticatorAttachment authenticatorAttachment, ResidentKeyRequirement residentKey, @Nullable UserVerificationRequirement userVerification) {
        this.authenticatorAttachment = authenticatorAttachment;
        this.residentKey = residentKey;
        this.requireResidentKey = residentKey == ResidentKeyRequirement.REQUIRED;
        this.userVerification = userVerification != null ? userVerification : UserVerificationRequirement.PREFERRED;
    }

    @Nullable
    public AuthenticatorAttachment getAuthenticatorAttachment() {
        return authenticatorAttachment;
    }

    @Nullable
    public ResidentKeyRequirement getResidentKey() {
        return residentKey;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        if (authenticatorAttachment != null) {
            map.put(AUTHENTICATOR_ATTACHMENT, authenticatorAttachment.toString());
        }
        if (residentKey != null) {
            map.put(RESIDENT_KEY, residentKey.toString());
        }
        map.put(REQUIRE_RESIDENT_KEY, requireResidentKey);
        map.put(USER_VERIFICATION, userVerification.toString());
        return map;
    }

    public static AuthenticatorSelectionCriteria fromMap(Map<String, ?> map) {
        ResidentKeyRequirement residentKeyRequirement = ResidentKeyRequirement.fromString((String) map.get(RESIDENT_KEY));
        if (residentKeyRequirement == null) {
            // Backwards compatibility with WebAuthn level 1
            if(map.get(REQUIRE_RESIDENT_KEY) == Boolean.TRUE) {
                residentKeyRequirement = ResidentKeyRequirement.REQUIRED;
            } else {
                residentKeyRequirement = ResidentKeyRequirement.DISCOURAGED;
            }
        }
        return new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.fromString((String) map.get(AUTHENTICATOR_ATTACHMENT)),
                residentKeyRequirement,
                UserVerificationRequirement.fromString((String) map.get(USER_VERIFICATION))
        );
    }
}

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

import static com.yubico.yubikit.fido.webauthn.Base64Utils.decode;
import static com.yubico.yubikit.fido.webauthn.Base64Utils.encode;

import javax.annotation.Nullable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class PublicKeyCredentialRequestOptions {
    private final static String CHALLENGE = "challenge";
    private final static String TIMEOUT = "timeout";
    private final static String RP_ID = "rpId";
    private final static String ALLOW_CREDENTIALS = "allowCredentials";
    private final static String USER_VERIFICATION = "userVerification";
    private final static String EXTENSIONS = "extensions";

    private final byte[] challenge;
    @Nullable
    private final Long timeout;
    @Nullable
    private final String rpId;
    private final List<PublicKeyCredentialDescriptor> allowCredentials;
    private final UserVerificationRequirement userVerification;
    @Nullable
    private final Extensions extensions;

    public PublicKeyCredentialRequestOptions(
            byte[] challenge,
            @Nullable Long timeout,
            @Nullable String rpId,
            @Nullable List<PublicKeyCredentialDescriptor> allowCredentials,
            @Nullable UserVerificationRequirement userVerification,
            @Nullable Extensions extensions
    ) {
        this.challenge = challenge;
        this.timeout = timeout;
        this.rpId = rpId;
        this.allowCredentials = allowCredentials != null ? allowCredentials : Collections.emptyList();
        this.userVerification = userVerification != null ? userVerification : UserVerificationRequirement.PREFERRED;
        this.extensions = extensions;
    }

    public byte[] getChallenge() {
        return challenge;
    }

    public @Nullable Long getTimeout() {
        return timeout;
    }

    @Nullable
    public String getRpId() {
        return rpId;
    }

    public List<PublicKeyCredentialDescriptor> getAllowCredentials() {
        return allowCredentials;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    @Nullable
    public Extensions getExtensions() {
        return extensions;
    }

    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(CHALLENGE, encode(challenge));
        if (timeout != null) {
            map.put(TIMEOUT, timeout);
        }
        if(rpId != null) {
            map.put(RP_ID, rpId);
        }
        List<Map<String, ?>> allowCredentialsList = new ArrayList<>();
        for (PublicKeyCredentialDescriptor cred : allowCredentials) {
            allowCredentialsList.add(cred.toMap());
        }
        map.put(ALLOW_CREDENTIALS, allowCredentialsList);
        map.put(USER_VERIFICATION, userVerification.toString());
        if (extensions != null) {
            map.put(EXTENSIONS, extensions);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    public static PublicKeyCredentialRequestOptions fromMap(Map<String, ?> map) {
        List<PublicKeyCredentialDescriptor> allowCredentials = null;
        List<Map<String, ?>> allowCredentialsList = (List<Map<String, ?>>) map.get(ALLOW_CREDENTIALS);
        if (allowCredentialsList != null) {
            allowCredentials = new ArrayList<>();
            for (Map<String, ?> cred : allowCredentialsList) {
                allowCredentials.add(PublicKeyCredentialDescriptor.fromMap(cred));
            }
        }

        Number timeout = ((Number) map.get(TIMEOUT));

        return new PublicKeyCredentialRequestOptions(
                decode(Objects.requireNonNull(map.get(CHALLENGE))),
                timeout == null ? null : timeout.longValue(),
                (String) map.get(RP_ID),
                allowCredentials,
                UserVerificationRequirement.fromString((String) map.get(USER_VERIFICATION)),
                null  // Extensions currently ignored
        );
    }
}

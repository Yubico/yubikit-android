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

public class PublicKeyCredentialCreationOptions {
    private final static String RP = "rp";
    private final static String USER = "user";
    private final static String CHALLENGE = "challenge";
    private final static String PUB_KEY_CRED_PARAMS = "pubKeyCredParams";
    private final static String TIMEOUT = "timeout";
    private final static String EXCLUDE_CREDENTIALS = "excludeCredentials";
    private final static String AUTHENTICATOR_SELECTION = "authenticatorSelection";
    private final static String ATTESTATION = "attestation";
    private final static String EXTENSIONS = "extensions";

    private final PublicKeyCredentialRpEntity rp;
    private final PublicKeyCredentialUserEntity user;
    private final byte[] challenge;
    private final List<PublicKeyCredentialParameters> pubKeyCredParams;
    @Nullable
    private final Long timeout;
    private final List<PublicKeyCredentialDescriptor> excludeCredentials;
    @Nullable
    private final AuthenticatorSelectionCriteria authenticatorSelection;
    private final String attestation;
    @Nullable
    private final Extensions extensions;

    public PublicKeyCredentialCreationOptions(
            PublicKeyCredentialRpEntity rp,
            PublicKeyCredentialUserEntity user,
            byte[] challenge,
            List<PublicKeyCredentialParameters> pubKeyCredParams,
            @Nullable Long timeout,
            @Nullable List<PublicKeyCredentialDescriptor> excludeCredentials,
            @Nullable AuthenticatorSelectionCriteria authenticatorSelection,
            @Nullable String attestation,
            @Nullable Extensions extensions
    ) {
        this.rp = rp;
        this.user = user;
        this.challenge = challenge;
        this.pubKeyCredParams = pubKeyCredParams;
        this.timeout = timeout;
        this.excludeCredentials = excludeCredentials != null ? excludeCredentials : Collections.emptyList();
        this.authenticatorSelection = authenticatorSelection;
        this.attestation = attestation != null ? attestation : AttestationConveyancePreference.NONE;
        this.extensions = extensions;
    }

    public PublicKeyCredentialRpEntity getRp() {
        return rp;
    }

    public PublicKeyCredentialUserEntity getUser() {
        return user;
    }

    public byte[] getChallenge() {
        return challenge;
    }

    public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    @Nullable
    public Long getTimeout() {
        return timeout;
    }

    public List<PublicKeyCredentialDescriptor> getExcludeCredentials() {
        return excludeCredentials;
    }

    @Nullable
    public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public String getAttestation() {
        return attestation;
    }

    @Nullable
    public Extensions getExtensions() {
        return extensions;
    }

    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(RP, rp.toMap());
        map.put(USER, user.toMap());
        map.put(CHALLENGE, encode(challenge));
        List<Map<String, ?>> paramsList = new ArrayList<>();
        for (PublicKeyCredentialParameters params : pubKeyCredParams) {
            paramsList.add(params.toMap());
        }
        map.put(PUB_KEY_CRED_PARAMS, paramsList);
        if (timeout != null) {
            map.put(TIMEOUT, timeout);
        }
        if (!excludeCredentials.isEmpty()) {
            List<Map<String, ?>> excludeCredentialsList = new ArrayList<>();
            for (PublicKeyCredentialDescriptor cred : excludeCredentials) {
                excludeCredentialsList.add(cred.toMap());
            }
            map.put(EXCLUDE_CREDENTIALS, excludeCredentialsList);
        }
        if (authenticatorSelection != null) {
            map.put(AUTHENTICATOR_SELECTION, authenticatorSelection.toMap());
        }
        map.put(ATTESTATION, attestation);
        if (extensions != null) {
            map.put(EXTENSIONS, extensions);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    public static PublicKeyCredentialCreationOptions fromMap(Map<String, ?> map) {
        List<PublicKeyCredentialParameters> pubKeyCredParams = new ArrayList<>();
        for (Map<String, ?> params : Objects.requireNonNull((List<Map<String, ?>>) map.get(PUB_KEY_CRED_PARAMS))) {
            pubKeyCredParams.add(PublicKeyCredentialParameters.fromMap(params));
        }
        List<PublicKeyCredentialDescriptor> excludeCredentials = null;
        List<Map<String, ?>> excludeCredentialsList = (List<Map<String, ?>>) map.get(EXCLUDE_CREDENTIALS);
        if (excludeCredentialsList != null) {
            excludeCredentials = new ArrayList<>();
            for (Map<String, ?> cred : excludeCredentialsList) {
                excludeCredentials.add(PublicKeyCredentialDescriptor.fromMap(cred));
            }
        }

        Map<String, ?> authenticatorSelection = (Map<String, ?>) map.get(AUTHENTICATOR_SELECTION);
        Number timeout = (Number) map.get(TIMEOUT);

        return new PublicKeyCredentialCreationOptions(
                PublicKeyCredentialRpEntity.fromMap(Objects.requireNonNull((Map<String, ?>) map.get(RP))),
                PublicKeyCredentialUserEntity.fromMap(Objects.requireNonNull((Map<String, ?>) map.get(USER))),
                decode(Objects.requireNonNull(map.get(CHALLENGE))),
                pubKeyCredParams,
                timeout == null ? null : timeout.longValue(),
                excludeCredentials,
                authenticatorSelection == null ? null : AuthenticatorSelectionCriteria.fromMap(authenticatorSelection),
                (String) map.get(ATTESTATION),
                null  // Extensions currently ignored
        );
    }
}
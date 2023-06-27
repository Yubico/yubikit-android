/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import javax.annotation.Nullable;

import org.apache.commons.codec.binary.Base64;

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
    private final long timeout;
    private final List<PublicKeyCredentialDescriptor> excludeCredentials;
    @Nullable
    private final AuthenticatorSelectionCriteria authenticatorSelection;
    private final AttestationConveyancePreference attestation;
    @Nullable
    private final Extensions extensions;

    public PublicKeyCredentialCreationOptions(
            PublicKeyCredentialRpEntity rp,
            PublicKeyCredentialUserEntity user,
            byte[] challenge,
            List<PublicKeyCredentialParameters> pubKeyCredParams,
            long timeout,
            @Nullable List<PublicKeyCredentialDescriptor> excludeCredentials,
            @Nullable AuthenticatorSelectionCriteria authenticatorSelection,
            @Nullable AttestationConveyancePreference attestation,
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

    public long getTimeout() {
        return timeout;
    }

    public List<PublicKeyCredentialDescriptor> getExcludeCredentials() {
        return excludeCredentials;
    }

    @Nullable
    public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public AttestationConveyancePreference getAttestation() {
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
        map.put(CHALLENGE, challenge);
        List<Map<String, ?>> paramsList = new ArrayList<>();
        for (PublicKeyCredentialParameters params : pubKeyCredParams) {
            paramsList.add(params.toMap());
        }
        map.put(PUB_KEY_CRED_PARAMS, paramsList);
        map.put(TIMEOUT, timeout);
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
        map.put(ATTESTATION, attestation.toString());
        if (extensions != null) {
            map.put(EXTENSIONS, extensions);
        }
        return map;
    }

    public Map<String, ?> toJsonMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(RP, rp.toMap());
        map.put(USER, user.toJsonMap());
        map.put(CHALLENGE, Base64.encodeBase64URLSafeString(challenge));
        List<Map<String, ?>> paramsList = new ArrayList<>();
        for (PublicKeyCredentialParameters params : pubKeyCredParams) {
            paramsList.add(params.toMap());
        }
        map.put(PUB_KEY_CRED_PARAMS, paramsList);
        map.put(TIMEOUT, timeout);
        if (!excludeCredentials.isEmpty()) {
            List<Map<String, ?>> excludeCredentialsList = new ArrayList<>();
            for (PublicKeyCredentialDescriptor cred : excludeCredentials) {
                excludeCredentialsList.add(cred.toJsonMap());
            }
            map.put(EXCLUDE_CREDENTIALS, excludeCredentialsList);
        }
        if (authenticatorSelection != null) {
            map.put(AUTHENTICATOR_SELECTION, authenticatorSelection.toMap());
        }
        map.put(ATTESTATION, attestation.toString());
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

        return new PublicKeyCredentialCreationOptions(
                PublicKeyCredentialRpEntity.fromMap(Objects.requireNonNull((Map<String, ?>) map.get(RP))),
                PublicKeyCredentialUserEntity.fromMap(Objects.requireNonNull((Map<String, ?>) map.get(USER))),
                Objects.requireNonNull((byte[]) map.get(CHALLENGE)),
                pubKeyCredParams,
                Objects.requireNonNull((Number) map.get(TIMEOUT)).longValue(),
                excludeCredentials,
                authenticatorSelection == null ? null : AuthenticatorSelectionCriteria.fromMap(authenticatorSelection),
                AttestationConveyancePreference.fromString((String) map.get(ATTESTATION)),
                null  // Extensions currently ignored
        );
    }

    @SuppressWarnings("unchecked")
    public static PublicKeyCredentialCreationOptions fromJsonMap(Map<String, ?> map) {
        List<PublicKeyCredentialParameters> pubKeyCredParams = new ArrayList<>();
        for (Map<String, ?> params : Objects.requireNonNull((List<Map<String, ?>>) map.get(PUB_KEY_CRED_PARAMS))) {
            pubKeyCredParams.add(PublicKeyCredentialParameters.fromMap(params));
        }
        List<PublicKeyCredentialDescriptor> excludeCredentials = null;
        List<Map<String, ?>> excludeCredentialsList = (List<Map<String, ?>>) map.get(EXCLUDE_CREDENTIALS);
        if (excludeCredentialsList != null) {
            excludeCredentials = new ArrayList<>();
            for (Map<String, ?> cred : excludeCredentialsList) {
                excludeCredentials.add(PublicKeyCredentialDescriptor.fromJsonMap(cred));
            }
        }

        Map<String, ?> authenticatorSelection = (Map<String, ?>) map.get(AUTHENTICATOR_SELECTION);

        return new PublicKeyCredentialCreationOptions(
                PublicKeyCredentialRpEntity.fromMap(Objects.requireNonNull((Map<String, ?>) map.get(RP))),
                PublicKeyCredentialUserEntity.fromJsonMap(Objects.requireNonNull((Map<String, ?>) map.get(USER))),
                Base64.decodeBase64(Objects.requireNonNull((String) map.get(CHALLENGE))),
                pubKeyCredParams,
                Objects.requireNonNull((Number) map.get(TIMEOUT)).longValue(),
                excludeCredentials,
                authenticatorSelection == null ? null : AuthenticatorSelectionCriteria.fromMap(authenticatorSelection),
                AttestationConveyancePreference.fromString((String) map.get(ATTESTATION)),
                null  // Extensions currently ignored
        );
    }
}
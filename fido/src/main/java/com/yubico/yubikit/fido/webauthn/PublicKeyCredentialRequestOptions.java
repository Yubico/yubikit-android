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

public class PublicKeyCredentialRequestOptions {
    private final static String CHALLENGE = "challenge";
    private final static String TIMEOUT = "timeout";
    private final static String RP_ID = "rpId";
    private final static String ALLOW_CREDENTIALS = "allowCredentials";
    private final static String USER_VERIFICATION = "userVerification";
    private final static String EXTENSIONS = "extensions";

    private final byte[] challenge;
    private final long timeout;
    @Nullable
    private final String rpId;
    private final List<PublicKeyCredentialDescriptor> allowCredentials;
    private final UserVerificationRequirement userVerification;
    // TODO: add attestation property
    // TODO: add attestationFormats property
    @Nullable
    private final Extensions extensions;

    public PublicKeyCredentialRequestOptions(byte[] challenge, long timeout, @Nullable String rpId, @Nullable List<PublicKeyCredentialDescriptor> allowCredentials, @Nullable UserVerificationRequirement userVerification, @Nullable Extensions extensions) {
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

    public long getTimeout() {
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

    public Map<String, ?> toJsonMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(CHALLENGE, Base64.encodeBase64URLSafeString(challenge));
        map.put(TIMEOUT, timeout);
        if(rpId != null) {
            map.put(RP_ID, rpId);
        }
        List<Map<String, ?>> allowCredentialsList = new ArrayList<>();
        for (PublicKeyCredentialDescriptor cred : allowCredentials) {
            allowCredentialsList.add(cred.toJsonMap());
        }
        map.put(ALLOW_CREDENTIALS, allowCredentialsList);
        map.put(USER_VERIFICATION, userVerification.toString());
        if (extensions != null) {
            map.put(EXTENSIONS, extensions);
        }
        return map;
    }

    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(CHALLENGE, challenge);
        map.put(TIMEOUT, timeout);
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
    public static PublicKeyCredentialRequestOptions fromJsonMap(Map<String, ?> map) {
        List<PublicKeyCredentialDescriptor> allowCredentials = null;
        List<Map<String, ?>> allowCredentialsList = (List<Map<String, ?>>) map.get(ALLOW_CREDENTIALS);
        if (allowCredentialsList != null) {
            allowCredentials = new ArrayList<>();
            for (Map<String, ?> cred : allowCredentialsList) {
                allowCredentials.add(PublicKeyCredentialDescriptor.fromJsonMap(cred));
            }
        }

        return new PublicKeyCredentialRequestOptions(
                Base64.decodeBase64(Objects.requireNonNull((String) map.get(CHALLENGE))),
                Objects.requireNonNull((Number) map.get(TIMEOUT)).longValue(),
                (String) map.get(RP_ID),
                allowCredentials,
                UserVerificationRequirement.fromString((String) map.get(USER_VERIFICATION)),
                null  // Extensions currently ignored
        );
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

        return new PublicKeyCredentialRequestOptions(
                Objects.requireNonNull((byte[]) map.get(CHALLENGE)),
                Objects.requireNonNull((Number) map.get(TIMEOUT)).longValue(),
                (String) map.get(RP_ID),
                allowCredentials,
                UserVerificationRequirement.fromString((String) map.get(USER_VERIFICATION)),
                null  // Extensions currently ignored
        );
    }
}

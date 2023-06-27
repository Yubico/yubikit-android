/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import javax.annotation.Nullable;

import org.apache.commons.codec.binary.Base64;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class AuthenticatorAssertionResponse extends AuthenticatorResponse {
    private static final String CLIENT_DATA_JSON = "clientDataJSON";
    private static final String AUTHENTICATOR_DATA = "authenticatorData";
    private static final String SIGNATURE = "signature";
    private static final String USER_HANDLE = "userHandle";
    private static final String CREDENTIAL_ID = "credentialId";

    private final byte[] authenticatorData;
    private final byte[] signature;
    @Nullable
    private final byte[] userHandle;
    private final byte[] credentialId;

    public AuthenticatorAssertionResponse(byte[] authenticatorData, byte[] clientDataJson, byte[] signature, @Nullable byte[] userHandle, byte[] credentialId) {
        super(clientDataJson);
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.userHandle = userHandle;
        this.credentialId = credentialId;
    }

    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getSignature() {
        return signature;
    }

    @Nullable
    public byte[] getUserHandle() {
        return userHandle;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    @Override
    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(AUTHENTICATOR_DATA, authenticatorData);
        map.put(CLIENT_DATA_JSON, getClientDataJson());
        map.put(SIGNATURE, signature);
        if (userHandle != null) {
            map.put(USER_HANDLE, userHandle);
        }
        map.put(CREDENTIAL_ID, credentialId);
        return map;
    }

    public Map<String, ?> toJsonMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(AUTHENTICATOR_DATA, Base64.encodeBase64URLSafeString(authenticatorData));
        map.put(CLIENT_DATA_JSON, Base64.encodeBase64URLSafeString(getClientDataJson()));
        map.put(SIGNATURE, Base64.encodeBase64URLSafeString(signature));
        if (userHandle != null) {
            map.put(USER_HANDLE, Base64.encodeBase64URLSafeString(userHandle));
        }
        map.put(CREDENTIAL_ID, Base64.encodeBase64URLSafeString(credentialId));
        return map;
    }

    public static AuthenticatorAssertionResponse fromMap(Map<String, ?> map) {
        return new AuthenticatorAssertionResponse(
                Objects.requireNonNull((byte[]) map.get(AUTHENTICATOR_DATA)),
                Objects.requireNonNull((byte[]) map.get(CLIENT_DATA_JSON)),
                Objects.requireNonNull((byte[]) map.get(SIGNATURE)),
                (byte[]) map.get(USER_HANDLE),
                Objects.requireNonNull((byte[]) map.get(CREDENTIAL_ID))
        );
    }

    public static AuthenticatorAssertionResponse fromJsonMap(Map<String, ?> map) {
        return new AuthenticatorAssertionResponse(
                Base64.decodeBase64(Objects.requireNonNull((String) map.get(AUTHENTICATOR_DATA))),
                Base64.decodeBase64(Objects.requireNonNull((String) map.get(CLIENT_DATA_JSON))),
                Base64.decodeBase64(Objects.requireNonNull((String) map.get(SIGNATURE))),
                Base64.decodeBase64((String) map.get(USER_HANDLE)),
                Base64.decodeBase64(Objects.requireNonNull((String) map.get(CREDENTIAL_ID)))
        );
    }
}

/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import javax.annotation.Nullable;

import com.yubico.yubikit.fido.Cbor;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class AuthenticatorAssertionResponse extends AuthenticatorResponse {
    private static final String CLIENT_DATA_JSON = "clientDataJson";
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

    public static AuthenticatorAssertionResponse fromMap(Map<String, ?> map) {
        return new AuthenticatorAssertionResponse(
                Objects.requireNonNull((byte[]) map.get(AUTHENTICATOR_DATA)),
                Objects.requireNonNull((byte[]) map.get(CLIENT_DATA_JSON)),
                Objects.requireNonNull((byte[]) map.get(SIGNATURE)),
                (byte[]) map.get(USER_HANDLE),
                Objects.requireNonNull((byte[]) map.get(CREDENTIAL_ID))
        );
    }

    @SuppressWarnings("unchecked")
    public static AuthenticatorAssertionResponse fromBytes(byte[] bytes) {
        return fromMap((Map<String, ?>) Objects.requireNonNull(Cbor.decode(bytes)));
    }
}

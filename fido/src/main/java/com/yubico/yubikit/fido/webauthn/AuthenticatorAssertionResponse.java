/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;


import static com.yubico.yubikit.fido.webauthn.Base64Utils.decode;
import static com.yubico.yubikit.fido.webauthn.Base64Utils.encode;

import javax.annotation.Nullable;

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
        map.put(AUTHENTICATOR_DATA, encode(authenticatorData));
        map.put(CLIENT_DATA_JSON, encode(getClientDataJson()));
        map.put(SIGNATURE, encode(signature));
        if (userHandle != null) {
            map.put(USER_HANDLE, encode(userHandle));
        }
        map.put(CREDENTIAL_ID, encode(credentialId));
        return map;
    }

    public static AuthenticatorAssertionResponse fromMap(Map<String, ?> map) {
        return new AuthenticatorAssertionResponse(
                decode(Objects.requireNonNull(map.get(AUTHENTICATOR_DATA))),
                decode(Objects.requireNonNull(map.get(CLIENT_DATA_JSON))),
                decode(Objects.requireNonNull(map.get(SIGNATURE))),
                decode(map.get(USER_HANDLE)),
                decode(Objects.requireNonNull(map.get(CREDENTIAL_ID)))
        );
    }
}

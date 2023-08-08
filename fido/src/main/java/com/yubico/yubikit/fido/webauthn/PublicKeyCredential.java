/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import static com.yubico.yubikit.fido.webauthn.AuthenticatorAssertionResponse.AUTHENTICATOR_DATA;
import static com.yubico.yubikit.fido.webauthn.Base64Utils.decode;
import static com.yubico.yubikit.fido.webauthn.Base64Utils.encode;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PublicKeyCredential extends Credential {
    static final String RAW_ID = "rawId";
    static final String RESPONSE = "response";

    static final String PUBLIC_KEY_CREDENTIAL_TYPE = "public-key";

    private final byte[] rawId;
    private final AuthenticatorResponse response;

    /**
     * Constructs a new Webauthn PublicKeyCredential object
     *
     * @param id       Credential id in base64 url safe encoding.
     * @param response Operation response.
     * @see AuthenticatorAttestationResponse
     * @see AuthenticatorAssertionResponse
     */
    public PublicKeyCredential(String id, AuthenticatorResponse response) {
        super(id, PUBLIC_KEY_CREDENTIAL_TYPE);
        this.rawId = decode(id);
        this.response = response;
    }

    /**
     * Constructs a new Webauthn PublicKeyCredential object
     *
     * @param id       Credential id in binary form.
     * @param response Operation response.
     * @see AuthenticatorAttestationResponse
     * @see AuthenticatorAssertionResponse
     */
    public PublicKeyCredential(byte[] id, AuthenticatorResponse response) {
        super(encode(id), PUBLIC_KEY_CREDENTIAL_TYPE);
        this.rawId = id;
        this.response = response;
    }

    public byte[] getRawId() {
        return Arrays.copyOf(rawId, rawId.length);
    }

    public AuthenticatorResponse getResponse() {
        return response;
    }

    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(ID, getId());
        map.put(TYPE, getType());
        map.put(RAW_ID, encode(getRawId()));
        map.put(RESPONSE, getResponse().toMap());
        return map;
    }

    @SuppressWarnings("unchecked")
    public static PublicKeyCredential fromMap(Map<String, ?> map) {
        if (!PUBLIC_KEY_CREDENTIAL_TYPE.equals(Objects.requireNonNull((String) map.get(TYPE)))) {
            throw new IllegalArgumentException("Expecting type=" + PUBLIC_KEY_CREDENTIAL_TYPE);
        }

        Map<String, ?> responseMap = Objects.requireNonNull((Map<String, ?>) map.get(RESPONSE));
        AuthenticatorResponse response;
        try {
            if (responseMap.containsKey(AUTHENTICATOR_DATA)) {
                response = AuthenticatorAssertionResponse.fromMap(responseMap);
            } else {
                response = AuthenticatorAttestationResponse.fromMap(responseMap);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Unknown AuthenticatorResponse format", e);
        }

        return new PublicKeyCredential(
                Objects.requireNonNull((String) map.get(ID)),
                response
        );
    }
}

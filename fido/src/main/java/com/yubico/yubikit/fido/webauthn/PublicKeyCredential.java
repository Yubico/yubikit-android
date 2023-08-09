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

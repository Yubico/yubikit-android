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

import com.yubico.yubikit.fido.ctap.Ctap2Session;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nullable;

public class PublicKeyCredential extends Credential {
    public static final String RAW_ID = "rawId";
    public static final String RESPONSE = "response";

    public static final String PUBLIC_KEY_CREDENTIAL_TYPE = "public-key";

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

    /**
     * Constructs new PublicKeyCredential from AssertionData
     *
     * @param assertion data base for the new credential
     * @param clientDataJson response client data
     * @param allowCredentials used for querying credential id for incomplete assertion objects
     * @return new PublicKeyCredential object
     */
    public static PublicKeyCredential fromAssertion(
            Ctap2Session.AssertionData assertion,
            byte[] clientDataJson,
            @Nullable List<PublicKeyCredentialDescriptor> allowCredentials) {
        byte[] userId = null;
        Map<String, ?> userMap = assertion.getUser();
        if (userMap != null) {
            // This is not a complete UserEntity object, it may contain only "id".
            userId = Objects.requireNonNull((byte[]) userMap.get(PublicKeyCredentialUserEntity.ID));
        }

        return new PublicKeyCredential(
                assertion.getCredentialId(allowCredentials),
                new AuthenticatorAssertionResponse(
                        clientDataJson,
                        assertion.getAuthenticatorData(),
                        assertion.getSignature(),
                        userId
                )
        );
    }
}

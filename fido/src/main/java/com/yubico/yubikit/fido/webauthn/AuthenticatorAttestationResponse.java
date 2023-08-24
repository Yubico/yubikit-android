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

import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.Cose;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nullable;

public class AuthenticatorAttestationResponse extends AuthenticatorResponse {
    public static final String ATTESTATION_OBJECT = "attestationObject";
    public static final String TRANSPORTS = "transports";
    public static final String AUTHENTICATOR_DATA = "authenticatorData";
    public static final String PUBLIC_KEY = "publicKey";
    public static final String PUBLIC_KEY_ALGORITHM = "publicKeyAlgorithm";

    private final byte[] authenticatorData;
    private final List<String> transports;
    @Nullable
    private final byte[] publicKey;
    @Nullable
    private final Integer publicKeyAlgorithm;
    private final byte[] attestationObject;

    public AuthenticatorAttestationResponse(
            byte[] clientDataJson,
            byte[] authenticatorData,
            List<String> transports,
            @Nullable byte[] publicKey,
            @Nullable Integer publicKeyAlgorithm,
            byte[] attestationObject) {
        super(clientDataJson);
        this.authenticatorData = authenticatorData;
        this.transports = transports;
        this.publicKey = publicKey;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.attestationObject = attestationObject;
    }

    @SuppressWarnings("unchecked")
    public AuthenticatorAttestationResponse(
            byte[] clientDataJson,
            byte[] authenticatorData,
            List<String> transports,
            @Nullable byte[] cosePublicKey,
            byte[] attestationObject) {
        super(clientDataJson);

        byte[] publicKeyBytes = null;
        Integer publicKeyAlgorithm = null;

        if (cosePublicKey != null) {
            try {
                Map<Integer, ?> decodedCosePublicKey = (Map<Integer, ?>) Cbor.decode(cosePublicKey);
                PublicKey pk = Cose.getPublicKey(decodedCosePublicKey);
                if (pk != null) {
                    publicKeyBytes = pk.getEncoded();
                    publicKeyAlgorithm = Cose.getAlgorithm(decodedCosePublicKey);
                }
            } catch (InvalidKeySpecException | NoSuchAlgorithmException | NullPointerException e) {
                // ignored
            }
        }


        this.authenticatorData = authenticatorData;
        this.transports = transports;
        this.publicKey = publicKeyBytes;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.attestationObject = attestationObject;
    }

    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    public List<String> getTransports()
    {
        return transports;
    }

    @Nullable
    public byte[] getPublicKey() {
        return publicKey;
    }

    @Nullable
    public Integer getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public byte[] getAttestationObject() {
        return attestationObject;
    }

    @Override
    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(CLIENT_DATA_JSON, Base64.encode(getClientDataJson()));
        map.put(AUTHENTICATOR_DATA, Base64.encode(authenticatorData));
        map.put(TRANSPORTS, transports);
        if (publicKey != null && publicKeyAlgorithm != null) {
            map.put(PUBLIC_KEY, Base64.encode(publicKey));
            map.put(PUBLIC_KEY_ALGORITHM, publicKeyAlgorithm);
        }
        map.put(ATTESTATION_OBJECT, Base64.encode(attestationObject));
        return map;
    }

    @SuppressWarnings("unchecked")
    public static AuthenticatorAttestationResponse fromMap(Map<String, ?> map) {
        String publicKey = (String) map.get(PUBLIC_KEY);
        Integer publicKeyAlgorithm = (Integer) map.get(PUBLIC_KEY_ALGORITHM);
        return new AuthenticatorAttestationResponse(
                Base64.decode(Objects.requireNonNull((String) map.get(CLIENT_DATA_JSON))),
                Base64.decode(Objects.requireNonNull((String) map.get(AUTHENTICATOR_DATA))),
                (List<String>) Objects.requireNonNull(map.get(TRANSPORTS)),
                publicKey == null ? null : Base64.decode(publicKey),
                publicKeyAlgorithm,
                Base64.decode(Objects.requireNonNull((String) map.get(ATTESTATION_OBJECT)))
        );
    }
}

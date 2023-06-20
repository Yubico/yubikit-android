/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import com.yubico.yubikit.fido.Cbor;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class AuthenticatorAttestationResponse extends AuthenticatorResponse {
    private static final String CLIENT_DATA_JSON = "clientDataJson";
    private static final String ATTESTATION_OBJECT = "attestationObject";

    private final byte[] attestationObject;

    public AuthenticatorAttestationResponse(byte[] clientDataJson, byte[] attestationObject) {
        super(clientDataJson);
        this.attestationObject = attestationObject;
    }

    public byte[] getAttestationObject() {
        return attestationObject;
    }

    @Override
    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(CLIENT_DATA_JSON, getClientDataJson());
        map.put(ATTESTATION_OBJECT, attestationObject);
        return map;
    }

    public static AuthenticatorAttestationResponse fromMap(Map<String, ?> map) {
        return new AuthenticatorAttestationResponse(
                Objects.requireNonNull((byte[]) map.get(CLIENT_DATA_JSON)),
                Objects.requireNonNull((byte[]) map.get(ATTESTATION_OBJECT))
        );
    }

    @SuppressWarnings("unchecked")
    public static AuthenticatorAttestationResponse fromBytes(byte[] bytes) {
        return fromMap((Map<String, ?>) Objects.requireNonNull(Cbor.decode(bytes)));
    }
}

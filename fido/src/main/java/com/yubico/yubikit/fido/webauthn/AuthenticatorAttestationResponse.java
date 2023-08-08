/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import static com.yubico.yubikit.fido.webauthn.Base64Utils.encode;
import static com.yubico.yubikit.fido.webauthn.Base64Utils.decode;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class AuthenticatorAttestationResponse extends AuthenticatorResponse {
    static final String ATTESTATION_OBJECT = "attestationObject";

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
        map.put(CLIENT_DATA_JSON, encode(getClientDataJson()));
        map.put(ATTESTATION_OBJECT, encode(attestationObject));
        return map;
    }

    public static AuthenticatorAttestationResponse fromMap(Map<String, ?> map) {
        return new AuthenticatorAttestationResponse(
                decode(Objects.requireNonNull(map.get(CLIENT_DATA_JSON))),
                decode(Objects.requireNonNull(map.get(ATTESTATION_OBJECT)))
        );
    }
}

/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import static com.yubico.yubikit.fido.webauthn.BinaryEncoding.doDecode;
import static com.yubico.yubikit.fido.webauthn.BinaryEncoding.doEncode;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class AuthenticatorAttestationResponse extends AuthenticatorResponse {
    private static final String CLIENT_DATA_JSON = "clientDataJSON";
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
        return toMap(BinaryEncoding.DEFAULT);
    }

    public Map<String, ?> toMap(BinaryEncoding binaryEncoding) {
        Map<String, Object> map = new HashMap<>();
        map.put(CLIENT_DATA_JSON, doEncode(getClientDataJson(), binaryEncoding));
        map.put(ATTESTATION_OBJECT, doEncode(attestationObject, binaryEncoding));
        return map;
    }

    public static AuthenticatorAttestationResponse fromMap(Map<String, ?> map) {
        return fromMap(map, BinaryEncoding.DEFAULT);
    }

    public static AuthenticatorAttestationResponse fromMap(Map<String, ?> map, BinaryEncoding binaryEncoding) {
        return new AuthenticatorAttestationResponse(
                doDecode(Objects.requireNonNull(map.get(CLIENT_DATA_JSON)), binaryEncoding),
                doDecode(Objects.requireNonNull(map.get(ATTESTATION_OBJECT)), binaryEncoding)
        );
    }
}

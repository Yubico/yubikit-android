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

import static com.yubico.yubikit.fido.webauthn.Base64Utils.decode;
import static com.yubico.yubikit.fido.webauthn.Base64Utils.encode;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class AuthenticatorAttestationResponse extends AuthenticatorResponse {
    public static final String TRANSPORTS = "transports";
    public static final String ATTESTATION_OBJECT = "attestationObject";

    private final List<String> transports;
    private final byte[] attestationObject;

    public AuthenticatorAttestationResponse(
            byte[] clientDataJson,
            List<String> transports,
            byte[] attestationObject) {
        super(clientDataJson);
        this.transports = transports;
        this.attestationObject = attestationObject;
    }

    public byte[] getAttestationObject() {
        return attestationObject;
    }

    public List<String> getTransports()
    {
        return transports;
    }

    @Override
    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(CLIENT_DATA_JSON, encode(getClientDataJson()));
        map.put(TRANSPORTS, transports);
        map.put(ATTESTATION_OBJECT, encode(attestationObject));
        return map;
    }

    @SuppressWarnings("unchecked")
    public static AuthenticatorAttestationResponse fromMap(Map<String, ?> map) {
        return new AuthenticatorAttestationResponse(
                decode(map.get(CLIENT_DATA_JSON)),
                (List<String>) Objects.requireNonNull(map.get(TRANSPORTS)),
                decode(Objects.requireNonNull(map.get(ATTESTATION_OBJECT)))
        );
    }
}

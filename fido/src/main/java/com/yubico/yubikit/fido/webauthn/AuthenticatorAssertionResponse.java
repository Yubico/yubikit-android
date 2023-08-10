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

import javax.annotation.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class AuthenticatorAssertionResponse extends AuthenticatorResponse {
    static final String AUTHENTICATOR_DATA = "authenticatorData";
    static final String SIGNATURE = "signature";
    static final String USER_HANDLE = "userHandle";

    private final byte[] authenticatorData;
    private final byte[] signature;
    @Nullable
    private final byte[] userHandle;

    public AuthenticatorAssertionResponse(
            byte[] clientDataJson,
            byte[] authenticatorData,
            byte[] signature,
            @Nullable byte[] userHandle
    ) {
        super(clientDataJson);
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.userHandle = userHandle;
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

    @Override
    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(CLIENT_DATA_JSON, encode(getClientDataJson()));
        map.put(AUTHENTICATOR_DATA, encode(authenticatorData));
        map.put(SIGNATURE, encode(signature));
        if (userHandle != null) {
            map.put(USER_HANDLE, encode(userHandle));
        }
        return map;
    }

    public static AuthenticatorAssertionResponse fromMap(Map<String, ?> map) {
        return new AuthenticatorAssertionResponse(
                decode(Objects.requireNonNull(map.get(CLIENT_DATA_JSON))),
                decode(Objects.requireNonNull(map.get(AUTHENTICATOR_DATA))),
                decode(Objects.requireNonNull(map.get(SIGNATURE))),
                decode(map.get(USER_HANDLE))
        );
    }
}

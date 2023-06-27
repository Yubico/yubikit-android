/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import java.util.Map;

public abstract class AuthenticatorResponse {
    private final byte[] clientDataJson;

    AuthenticatorResponse(byte[] clientDataJson) {
        this.clientDataJson = clientDataJson;
    }

    public byte[] getClientDataJson() {
        return clientDataJson;
    }

    public abstract Map<String, ?> toMap();
    public abstract Map<String, ?> toMap(BinaryEncoding binaryEncoding);
}

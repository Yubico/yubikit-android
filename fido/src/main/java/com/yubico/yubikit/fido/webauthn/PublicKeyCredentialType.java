/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

public enum PublicKeyCredentialType {
    PUBLIC_KEY;

    @Override
    public String toString() {
        return name().replace("_", "-").toLowerCase();
    }

    public static PublicKeyCredentialType fromString(String value) {
        return PublicKeyCredentialType.valueOf(value
                .replace("-", "_")
                .toUpperCase()
        );
    }
}

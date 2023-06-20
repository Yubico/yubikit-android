/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import javax.annotation.Nullable;

public enum AuthenticatorAttachment {
    PLATFORM, CROSS_PLATFORM;

    @Override
    public String toString() {
        return name().replace("_", "-").toLowerCase();
    }

    @Nullable
    public static AuthenticatorAttachment fromString(@Nullable String value) {
        if(value == null) {
            return null;
        }
        try {
            return AuthenticatorAttachment.valueOf(value
                    .replace("-", "_")
                    .toUpperCase()
            );
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}

/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import javax.annotation.Nullable;

public enum AttestationConveyancePreference {
    NONE, INDIRECT, DIRECT, ENTERPRISE;

    @Override
    public String toString() {
        return name().toLowerCase();
    }

    @Nullable
    public static AttestationConveyancePreference fromString(@Nullable String value) {
        if(value == null) {
            return null;
        }
        try {
            return AttestationConveyancePreference.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}

package com.yubico.yubikit.fido.webauthn;

import javax.annotation.Nullable;

public enum ResidentKeyRequirement {
    REQUIRED, PREFERRED, DISCOURAGED;

    @Override
    public String toString() {
        return name().toLowerCase();
    }

    @Nullable
    public static ResidentKeyRequirement fromString(@Nullable String value) {
        if(value == null) {
            return null;
        }
        try {
            return ResidentKeyRequirement.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}

/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PublicKeyCredentialParameters {
    private static final String TYPE = "type";
    private static final String ALG = "alg";

    private final PublicKeyCredentialType type;
    private final int alg;

    public PublicKeyCredentialParameters(PublicKeyCredentialType type, int alg) {
        this.type = type;
        this.alg = alg;
    }

    public PublicKeyCredentialType getType() {
        return type;
    }

    public int getAlg() {
        return alg;
    }

    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(TYPE, type.toString());
        map.put(ALG, alg);
        return map;
    }

    public static PublicKeyCredentialParameters fromMap(Map<String, ?> map) {
        return new PublicKeyCredentialParameters(
                PublicKeyCredentialType.fromString(Objects.requireNonNull((String) map.get(TYPE))),
                Objects.requireNonNull((Integer) map.get(ALG))
        );
    }
}

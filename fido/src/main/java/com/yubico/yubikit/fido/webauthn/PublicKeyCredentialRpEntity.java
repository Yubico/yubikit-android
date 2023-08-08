/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nullable;

public class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
    private static final String ID = "id";
    @Nullable
    private final String id;

    public PublicKeyCredentialRpEntity(String name, @Nullable String id) {
        super(name);
        this.id = id;
    }

    @Nullable
    public String getId() {
        return id;
    }

    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(NAME, getName());
        if (id != null) {
            map.put(ID, id);
        }
        return map;
    }

    public static PublicKeyCredentialRpEntity fromMap(Map<String, ?> map) {
        return new PublicKeyCredentialRpEntity(
                Objects.requireNonNull((String) map.get(NAME)),
                (String) map.get(ID)
        );
    }
}

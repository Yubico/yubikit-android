/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import javax.annotation.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PublicKeyCredentialRpEntity {
    private static final String ID = "id";
    private static final String NAME = "name";

    private final String name;
    @Nullable
    private final String id;

    public PublicKeyCredentialRpEntity(String name, @Nullable String id) {
        this.name = name;
        this.id = id;
    }

    public String getName() {
        return name;
    }

    @Nullable
    public String getId() {
        return id;
    }

    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(NAME, name);
        if(id != null) {
            map.put(ID, id);
        }
        return map;
    }

    public static PublicKeyCredentialRpEntity fromMap(Map<String, ?> map) {
        return new PublicKeyCredentialRpEntity(
                Objects.requireNonNull((String) map.get(NAME)), (String) map.get(ID)
        );
    }
}

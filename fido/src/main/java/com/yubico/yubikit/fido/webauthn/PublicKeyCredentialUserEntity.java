/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PublicKeyCredentialUserEntity {
    private static final String ID = "id";
    private static final String NAME = "name";
    private static final String DISPLAY_NAME = "displayName";

    private final String name;
    private final byte[] id;
    private final String displayName;

    public PublicKeyCredentialUserEntity(String name, byte[] id, String displayName) {
        this.name = name;
        this.id = id;
        this.displayName = displayName;
    }

    public String getName() {
        return name;
    }

    public byte[] getId() {
        return id;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(NAME, name);
        map.put(ID, id);
        map.put(DISPLAY_NAME, displayName);
        return map;
    }

    public static PublicKeyCredentialUserEntity fromMap(Map<String, ?> map) {
        return new PublicKeyCredentialUserEntity(
                Objects.requireNonNull((String) map.get(NAME)),
                Objects.requireNonNull((byte[]) map.get(ID)),
                Objects.requireNonNull((String) map.get(DISPLAY_NAME))
        );
    }
}

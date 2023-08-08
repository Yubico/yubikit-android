/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import static com.yubico.yubikit.fido.webauthn.Base64Utils.decode;
import static com.yubico.yubikit.fido.webauthn.Base64Utils.encode;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
    public static final String ID = "id";
    public static final String DISPLAY_NAME = "displayName";

    private final byte[] id;
    private final String displayName;

    public PublicKeyCredentialUserEntity(String name, byte[] id, String displayName) {
        super(name);
        this.id = id;
        this.displayName = displayName;
    }

    public byte[] getId() {
        return id;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(NAME, getName());
        map.put(ID, encode(id));
        map.put(DISPLAY_NAME, displayName);
        return map;
    }

    public static PublicKeyCredentialUserEntity fromMap(Map<String, ?> map) {
        return new PublicKeyCredentialUserEntity(
                Objects.requireNonNull((String) map.get(NAME)),
                decode(Objects.requireNonNull(map.get(ID))),
                Objects.requireNonNull((String) map.get(DISPLAY_NAME))
        );
    }
}

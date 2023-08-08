/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

public class PublicKeyCredentialEntity {
    public static final String NAME = "name";
    private final String name;

    public PublicKeyCredentialEntity(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}

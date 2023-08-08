/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

public class Credential {
    static final String ID = "id";
    static final String TYPE = "type";

    private final String id;
    private final String type;

    /**
     * Webauthn Credential interface
     *
     * @param id The credential’s identifier. The requirements for the identifier are distinct for each type of credential.
     * @param type Specifies the credential type represented by this object
     */
    public Credential(String id, String type) {
        this.id = id;
        this.type = type;
    }

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }
}

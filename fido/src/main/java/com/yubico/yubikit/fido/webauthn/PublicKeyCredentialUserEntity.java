/*
 * Copyright (C) 2020-2023 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.fido.webauthn;

import com.yubico.yubikit.core.internal.codec.Base64;

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

    public Map<String, ?> toMap(SerializationType serializationType) {
        Map<String, Object> map = new HashMap<>();
        map.put(NAME, getName());
        switch (serializationType) {
            case JSON:
                map.put(ID, Base64.encode(id));
                break;
            case CBOR:
                map.put(ID, id);
                break;
        }
        map.put(DISPLAY_NAME, displayName);
        return map;
    }

//    public Map<String, ?> toMap() {
//        return toMap(SerializationType.DEFAULT);
//    }

    public static PublicKeyCredentialUserEntity fromMap(Map<String, ?> map, SerializationType serializationType) {
        return new PublicKeyCredentialUserEntity(
                Objects.requireNonNull((String) map.get(NAME)),
                serializationType == SerializationType.JSON
                        ? Base64.decode(Objects.requireNonNull((String) map.get(ID)))
                        : Objects.requireNonNull((byte[]) map.get(ID)),
                Objects.requireNonNull((String) map.get(DISPLAY_NAME))
        );
    }

//    public static PublicKeyCredentialUserEntity fromMap(Map<String, ?> map) {
//        return fromMap(map, SerializationType.DEFAULT);
//    }
}

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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nullable;

public class PublicKeyCredentialDescriptor {
    public static final String TYPE = "type";
    public static final String ID = "id";
    public static final String TRANSPORTS = "transports";

    private final String type;
    private final byte[] id;
    @Nullable
    private final List<String> transports;

    public PublicKeyCredentialDescriptor(String type, byte[] id) {
        this.type = type;
        this.id = id;
        this.transports = null;
    }

    public PublicKeyCredentialDescriptor(String type, byte[] id, @Nullable List<String> transports) {
        this.type = type;
        this.id = id;
        this.transports = transports;
    }

    public String getType() {
        return type;
    }

    public byte[] getId() {
        return id;
    }

    @Nullable
    public List<String> getTransports() {
        return transports;
    }

    public Map<String, ?> toMap(SerializationType serializationType) {
        Map<String, Object> map = new HashMap<>();
        map.put(TYPE, type);
        switch (serializationType) {
            case JSON:
                map.put(ID, Base64.encode(id));
                break;
            case CBOR:
                map.put(ID, id);
                break;
        }
        if (transports != null) {
            map.put(TRANSPORTS, transports);
        }
        return map;
    }

    public Map<String, ?> toMap() {
        return toMap(SerializationType.DEFAULT);
    }

    @SuppressWarnings("unchecked")
    public static PublicKeyCredentialDescriptor fromMap(
            Map<String, ?> map,
            SerializationType serializationType
    ) {
        return new PublicKeyCredentialDescriptor(
                Objects.requireNonNull((String) map.get(TYPE)),
                serializationType == SerializationType.JSON
                        ? Base64.decode(Objects.requireNonNull((String) map.get(ID)))
                        : Objects.requireNonNull((byte[]) map.get(ID)),
                (List<String>) map.get(TRANSPORTS)
        );
    }

    public static PublicKeyCredentialDescriptor fromMap(Map<String, ?> map) {
        return fromMap(map, SerializationType.DEFAULT);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PublicKeyCredentialDescriptor that = (PublicKeyCredentialDescriptor) o;

        if (!type.equals(that.type)) return false;
        if (!Arrays.equals(id, that.id)) return false;
        return Objects.equals(transports, that.transports);
    }

    @Override
    public int hashCode() {
        int result = type.hashCode();
        result = 31 * result + Arrays.hashCode(id);
        result = 31 * result + (transports != null ? transports.hashCode() : 0);
        return result;
    }
}

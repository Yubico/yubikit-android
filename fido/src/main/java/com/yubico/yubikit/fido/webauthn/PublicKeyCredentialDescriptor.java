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

import javax.annotation.Nullable;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

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

    public Map<String, ?> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put(TYPE, type);
        map.put(ID, Base64.encode(id));
        if (transports != null) {
            map.put(TRANSPORTS, transports);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    public static PublicKeyCredentialDescriptor fromMap(Map<String, ?> map) {
        return new PublicKeyCredentialDescriptor(
                Objects.requireNonNull((String) map.get(TYPE)),
                Base64.decode(Objects.requireNonNull((String) map.get(ID))),
                (List<String>) map.get(TRANSPORTS)
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialDescriptor that = (PublicKeyCredentialDescriptor) o;
        return type.equals(that.type) &&
                Arrays.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(type);
        result = 31 * result + Arrays.hashCode(id);
        return result;
    }
}

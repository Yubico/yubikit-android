/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import static com.yubico.yubikit.fido.webauthn.BinaryEncoding.doDecode;
import static com.yubico.yubikit.fido.webauthn.BinaryEncoding.doEncode;

import org.apache.commons.codec.binary.Base64;

import javax.annotation.Nullable;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class PublicKeyCredentialDescriptor {
    private static final String TYPE = "type";
    private static final String ID = "id";
    private static final String TRANSPORTS = "transports";

    private final PublicKeyCredentialType type;
    private final byte[] id;
    @Nullable
    private final List<String> transports;

    public PublicKeyCredentialDescriptor(PublicKeyCredentialType type, byte[] id, @Nullable List<String> transports) {
        this.type = type;
        this.id = id;
        this.transports = transports;
    }

    public PublicKeyCredentialType getType() {
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
        return toMap(BinaryEncoding.DEFAULT);
    }

    public Map<String, ?> toMap(BinaryEncoding binaryEncoding) {
        Map<String, Object> map = new HashMap<>();
        map.put(TYPE, type.toString());
        map.put(ID, doEncode(id, binaryEncoding));
        if (transports != null && !transports.isEmpty()) {
            map.put(TRANSPORTS, transports);
        }
        return map;
    }

    public static PublicKeyCredentialDescriptor fromMap(Map<String, ?> map) {
        return fromMap(map, BinaryEncoding.DEFAULT);
    }

    @SuppressWarnings("unchecked")
    public static PublicKeyCredentialDescriptor fromMap(Map<String, ?> map, BinaryEncoding binaryEncoding) {
        return new PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.fromString(Objects.requireNonNull((String) map.get(TYPE))),
                doDecode(Objects.requireNonNull(map.get(ID)), binaryEncoding),
                (List<String>) map.get(TRANSPORTS)
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialDescriptor that = (PublicKeyCredentialDescriptor) o;
        return type == that.type &&
                Arrays.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(type);
        result = 31 * result + Arrays.hashCode(id);
        return result;
    }
}

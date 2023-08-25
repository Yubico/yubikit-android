/*
 * Copyright (C) 2023 Yubico.
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

import com.yubico.yubikit.fido.Cbor;

import java.nio.ByteBuffer;
import java.util.Map;

/**
 * Webauthn AttestedCredentialData structure
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attested-credential-data">6.5.1. Attested Credential Data</a>
 */
public class AttestedCredentialData {
    private final byte[] aaguid;
    private final byte[] credentialId;
    private final Map<Integer, ?> cosePublicKey;

    public AttestedCredentialData(
            byte[] aaguid,
            byte[] credentialId,
            Map<Integer, ?> cosePublicKey
    ) {
        this.aaguid = aaguid;
        this.credentialId = credentialId;
        this.cosePublicKey = cosePublicKey;
    }

    @SuppressWarnings("unchecked")
    public static AttestedCredentialData parseFrom(ByteBuffer buffer) {
        if (buffer.capacity() < 18) {
            throw new IllegalArgumentException("Invalid attested credential data");
        }

        final byte[] aaguid = new byte[16];
        buffer.get(aaguid);
        int credentialIdLength = buffer.getShort();

        if (buffer.capacity() < 18 + credentialIdLength) {
            throw new IllegalArgumentException("Invalid attested credential data");
        }

        final byte[] credentialId = new byte[credentialIdLength];
        buffer.get(credentialId);
        Map<Integer, ?> cosePublicKey = (Map<Integer, ?>) Cbor.decodeFrom(buffer);
        if (cosePublicKey == null) {
            throw new IllegalArgumentException("Invalid public key data");
        }

        return new AttestedCredentialData(
                aaguid,
                credentialId,
                cosePublicKey
        );
    }

    @SuppressWarnings("unused")
    public byte[] getAaguid() {
        return aaguid;
    }

    @SuppressWarnings("unused")
    public byte[] getCredentialId() {
        return credentialId;
    }

    @SuppressWarnings("unused")
    public Map<Integer, ?> getCosePublicKey() {
        return cosePublicKey;
    }
}

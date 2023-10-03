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
import com.yubico.yubikit.fido.ctap.Ctap2Session;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Webauthn AttestationObject which exposes attestation authenticator data.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation">6.5. Attestation</a>
 */
public class AttestationObject {
    public static final String KEY_FORMAT = "fmt";
    public static final String KEY_AUTHENTICATOR_DATA = "authData";
    public static final String KEY_ATTESTATION_STATEMENT = "attStmt";

    private final String format;
    private final AuthenticatorData authenticatorData;
    private final Map<String, ?> attestationStatement;

    public AttestationObject(
            String format,
            AuthenticatorData authenticatorData,
            Map<String, ?> attestationStatement
    ) {
        this.format = format;
        this.authenticatorData = authenticatorData;
        this.attestationStatement = attestationStatement;
    }

    static public AttestationObject fromCredential(Ctap2Session.CredentialData credential) {
        return new AttestationObject(
                credential.getFormat(),
                AuthenticatorData.parseFrom(ByteBuffer.wrap(credential.getAuthenticatorData())),
                credential.getAttestationStatement()
        );
    }

    @SuppressWarnings("unused")
    public String getFormat() {
        return format;
    }

    public AuthenticatorData getAuthenticatorData() {
        return authenticatorData;
    }

    @SuppressWarnings("unused")
    public Map<String, ?> getAttestationStatement() {
        return attestationStatement;
    }

    public byte[] toBytes() {
        Map<String, Object> attestationObject = new HashMap<>();
        attestationObject.put(AttestationObject.KEY_FORMAT, format);
        attestationObject.put(AttestationObject.KEY_AUTHENTICATOR_DATA, authenticatorData.getBytes());
        attestationObject.put(AttestationObject.KEY_ATTESTATION_STATEMENT, attestationStatement);
        return Cbor.encode(attestationObject);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AttestationObject that = (AttestationObject) o;

        if (!format.equals(that.format)) return false;
        if (!authenticatorData.equals(that.authenticatorData)) return false;
        return Arrays.equals(
                Cbor.encode(attestationStatement),
                Cbor.encode(that.attestationStatement));
    }

    @Override
    public int hashCode() {
        int result = format.hashCode();
        result = 31 * result + authenticatorData.hashCode();
        result = 31 * result + Arrays.hashCode(Cbor.encode(attestationStatement));
        return result;
    }
}

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
import com.yubico.yubikit.fido.Cose;
import com.yubico.yubikit.fido.ctap.Ctap2Session;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nullable;

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
    private final byte[] authenticatorData;
    private final Map<String, ?> attestationStatement;

    private final byte[] credentialId;
    @Nullable
    private final byte[] publicKey;
    private final int publicKeyAlgorithm;

    public AttestationObject(
            String format,
            byte[] authenticatorData,
            Map<String, ?> attestationStatement
    ) {
        this.format = format;
        this.authenticatorData = Arrays.copyOf(authenticatorData, authenticatorData.length);
        this.attestationStatement = attestationStatement;

        // parse authenticator data
        AuthenticatorData attestationAuthenticatorData =
                AuthenticatorData.parseFrom(ByteBuffer.wrap(this.authenticatorData));

        if (!attestationAuthenticatorData.isAt()) {
            throw new IllegalArgumentException("Invalid attestation for makeCredential");
        }

        AttestedCredentialData attestedCredentialData =
                Objects.requireNonNull(attestationAuthenticatorData.getAttestedCredentialData());
        this.credentialId = attestedCredentialData.getCredentialId();

        // compute public key information
        Map<Integer, ?> cosePublicKey = attestedCredentialData.getCosePublicKey();
        this.publicKeyAlgorithm = Cose.getAlgorithm(cosePublicKey);
        byte[] resultPublicKey = null;
        try {
            PublicKey publicKey = Cose.getPublicKey(cosePublicKey);
            resultPublicKey = publicKey == null
                    ? null
                    : publicKey.getEncoded();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException exception) {
            // library does not support this public key format
        }
        this.publicKey = resultPublicKey;
    }

    static public AttestationObject fromCredential(Ctap2Session.CredentialData credential) {
        return new AttestationObject(
                credential.getFormat(),
                credential.getAuthenticatorData(),
                credential.getAttestationStatement()
        );
    }

    public byte[] getCredentialId() {
        return Arrays.copyOf(credentialId, credentialId.length);
    }

    @Nullable
    public byte[] getPublicKey() {
        return publicKey == null ? null : Arrays.copyOf(publicKey, publicKey.length);
    }

    public int getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    @SuppressWarnings("unused")
    public String getFormat() {
        return format;
    }

    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    @SuppressWarnings("unused")
    public Map<String, ?> getAttestationStatement() {
        return attestationStatement;
    }

    public byte[] toBytes() {
        Map<String, Object> attestationObject = new HashMap<>();
        attestationObject.put(AttestationObject.KEY_FORMAT, format);
        attestationObject.put(AttestationObject.KEY_AUTHENTICATOR_DATA, authenticatorData);
        attestationObject.put(AttestationObject.KEY_ATTESTATION_STATEMENT, attestationStatement);
        return Cbor.encode(attestationObject);
    }
}

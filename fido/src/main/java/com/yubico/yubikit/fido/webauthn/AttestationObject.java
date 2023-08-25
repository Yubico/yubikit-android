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
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nullable;

/**
 * Webauthn AttestationObject which exposes attestation authenticator data.
 * <p>
 * Internal use only
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
        AttestationAuthenticatorData attestationAuthenticatorData =
                AttestationAuthenticatorData.fromBytes(this.authenticatorData);

        this.credentialId = attestationAuthenticatorData.getCredentialId();

        // compute public key information
        Map<Integer, ?> cosePublicKey = attestationAuthenticatorData.getCosePublicKey();
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
        byte[] authenticatorData = credential.getAuthenticatorData();

        return new AttestationObject(
                credential.getFormat(),
                authenticatorData,
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

    /**
     * Helper class used for decoding authenticator data created during makeCredential
     * <p>
     * Internal use only
     * <p>
     *
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data">6.1. Authenticator Data</a>
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attested-credential-data">6.5.1. Attested Credential Data</a>
     */
    private static class AttestationAuthenticatorData {
        @SuppressWarnings("unused")
        private static final int FLAG_UP = 0;
        @SuppressWarnings("unused")
        private static final int FLAG_UV = 2;
        private static final int FLAG_AT = 6;
        private static final int FLAG_ED = 7;

        private final byte[] rpIdHash;
        private final byte flags;
        private final int signCount;

        private final byte[] aaguid;
        private final byte[] credentialId;
        private final Map<Integer, ?> cosePublicKey;
        @Nullable
        private final byte[] extensions;

        static boolean getFlag(byte flags, int bitIndex) {
            return (flags >> bitIndex & 1) == 1;
        }

        AttestationAuthenticatorData(
                byte[] rpIdHash,
                byte flags,
                int signCount,
                byte[] aaguid,
                byte[] credentialId,
                Map<Integer, ?> cosePublicKey,
                @Nullable byte[] extensions
        ) {
            this.rpIdHash = rpIdHash;
            this.flags = flags;
            this.signCount = signCount;
            this.aaguid = aaguid;
            this.credentialId = credentialId;
            this.cosePublicKey = cosePublicKey;
            this.extensions = extensions;
        }

        @SuppressWarnings("unchecked")
        static AttestationAuthenticatorData fromBytes(byte[] data) {
            if (data.length < 37) {
                throw new IllegalArgumentException("Invalid authenticatorData data");
            }
            final byte[] rpIdHash = Arrays.copyOfRange(data, 0, 32);
            final byte flags = data[32];
            final int signCount = ByteBuffer.wrap(data, 33, 4).order(ByteOrder.BIG_ENDIAN).getInt();

            boolean flagAT = getFlag(flags, FLAG_AT);
            boolean flagED = getFlag(flags, FLAG_ED);

            if (!flagAT) {
                throw new IllegalArgumentException("Attestation authenticatorData missing AT flag");
            }

            if (data.length < 37 + 18) {
                throw new IllegalArgumentException("Invalid attested credential data");
            }

            final byte[] aaguid = Arrays.copyOfRange(data, 37, 52);
            int credentialIdLength = (data[53] & 0xFF) << 8 | (data[54] & 0xFF);

            if (data.length < 37 + 18 + credentialIdLength) {
                throw new IllegalArgumentException("Invalid attested credential data");
            }

            final byte[] credentialId = Arrays.copyOfRange(data, 55, 55 + credentialIdLength);
            int credentialPublicKeyIndex = 55 + credentialIdLength;
            Map<String, ?> decodedPublicKey = (Map<String, ?>) Cbor.decodePart(
                    data,
                    credentialPublicKeyIndex,
                    data.length - credentialPublicKeyIndex
            );

            final Map<Integer, ?> cosePublicKey = (Map<Integer, ?>) decodedPublicKey.get("object");
            if (cosePublicKey == null) {
                throw new IllegalArgumentException("Invalid public key data");
            }

            int extensionsIndex = (Integer) decodedPublicKey.get("index");
            int extensionsDataLength = data.length - extensionsIndex;

            // if there are any remaining data after the public key, use it for extensions
            byte[] extensions;
            if (!flagED) {
                if (extensionsDataLength != 0) {
                    throw new IllegalArgumentException("Unexpected extensions data");
                }
                extensions = null;
            } else {
                if (extensionsDataLength == 0) {
                    throw new IllegalArgumentException("Missing extensions data");
                }
                extensions = Arrays.copyOfRange(data, extensionsIndex, extensionsDataLength);
            }

            return new AttestationAuthenticatorData(
                    rpIdHash,
                    flags,
                    signCount,
                    aaguid,
                    credentialId,
                    cosePublicKey,
                    extensions
            );
        }

        @SuppressWarnings("unused")
        byte[] getRpIdHash() {
            return rpIdHash;
        }

        @SuppressWarnings("unused")
        byte getFlags() {
            return flags;
        }

        @SuppressWarnings("unused")
        int getSignCount() {
            return signCount;
        }

        @SuppressWarnings("unused")
        byte[] getAaguid() {
            return aaguid;
        }

        byte[] getCredentialId() {
            return credentialId;
        }

        Map<Integer, ?> getCosePublicKey() {
            return cosePublicKey;
        }

        @Nullable
        @SuppressWarnings("unused")
        byte[] getExtensions() {
            return extensions;
        }
    }
}

/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.fido;

import android.os.Parcel;
import android.os.Parcelable;

import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse;

/**
 * {@code MakeCredentialResponse} returned by authenticator when a PublicKeyCredential/MakeCredentialsOptions is passed,
 * Provides a cryptographic root of trust for the new key pair that has been generated.
 * This response should be sent to the relying party's server to complete the creation of the credential.
 */
public class MakeCredentialResponse implements Parcelable, AuthenticatorResponse {
    /**
     * Public Key Credential
     * contains an attestation statement verifiable by the WebAuthn Relying Party
     *
     * This attribute contains an attestation object, which is opaque to, and cryptographically protected against tampering by, the client.
     * The attestation object contains both authenticator data and an attestation statement.
     * The former contains the AAGUID, a unique credential ID, and the credential public key.
     * The contents of the attestation statement are determined by the attestation statement format used by the authenticator.
     * It also contains any additional information that the Relying Party's server requires to validate the attestation statement,
     * as well as to decode and validate the authenticator data along with the JSON-serialized client data.
     */
    private final byte[] attestationObject;

    /**
     * JSON-serialized client data constructed from collectedClientData whose fields are:
     * type
     * The string "webauthn.create".
     *
     * challenge
     * The base64url encoding of options.challenge.
     *
     * origin
     * The serialization of callerOrigin.
     *
     * tokenBinding
     * The status of Token Binding between the client and the callerOrigin, as well as the Token Binding ID associated with callerOrigin, if one is available.
     */
    private final byte[] clientDataJSON;

    /**
     * A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
     */
    private final byte[] keyHandle;


    MakeCredentialResponse(AuthenticatorAttestationResponse response) {
        keyHandle = response.getKeyHandle();
        clientDataJSON = response.getClientDataJSON();
        attestationObject = response.getAttestationObject();
    }

    protected MakeCredentialResponse(Parcel in) {
        keyHandle = in.createByteArray();
        clientDataJSON = in.createByteArray();
        attestationObject = in.createByteArray();
    }

    public static final Creator<MakeCredentialResponse> CREATOR = new Creator<MakeCredentialResponse>() {
        @Override
        public MakeCredentialResponse createFromParcel(Parcel in) {
            return new MakeCredentialResponse(in);
        }

        @Override
        public MakeCredentialResponse[] newArray(int size) {
            return new MakeCredentialResponse[size];
        }
    };

    /**
     * @return Public Key Credential
     * contains an attestation statement verifiable by the WebAuthn Relying Party
     *
     * This attribute contains an attestation object, which is opaque to, and cryptographically protected against tampering by, the client.
     * The attestation object contains both authenticator data and an attestation statement.
     * The former contains the AAGUID, a unique credential ID, and the credential public key.
     * The contents of the attestation statement are determined by the attestation statement format used by the authenticator.
     * It also contains any additional information that the Relying Party's server requires to validate the attestation statement,
     * as well as to decode and validate the authenticator data along with the JSON-serialized client data.
     */
    public byte[] getAttestationObject() {
        return attestationObject;
    }

    /**
     * @return JSON-serialized client data constructed from collectedClientData whose fields are:
     * type
     * The string "webauthn.create".
     *
     * challenge
     * The base64url encoding of options.challenge.
     *
     * origin
     * The serialization of callerOrigin.
     *
     * tokenBinding
     * The status of Token Binding between the client and the callerOrigin, as well as the Token Binding ID associated with callerOrigin, if one is available.
     */
    public byte[] getClientDataJSON() {
        return clientDataJSON;
    }

    /**
     * @return A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
     */
    public byte[] getKeyHandle() {
        return keyHandle;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeByteArray(keyHandle);
        dest.writeByteArray(clientDataJSON);
        dest.writeByteArray(attestationObject);
    }
}

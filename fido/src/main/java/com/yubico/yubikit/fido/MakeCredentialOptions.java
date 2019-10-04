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

import com.google.android.gms.fido.fido2.api.common.EC2Algorithm;
import com.google.android.gms.fido.fido2.api.common.RSAAlgorithm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * {@code MakeCredentialOptions} represents request to authenticator from server to register key/fingerprint,
 * holds options passed to authenticator in order to create a PublicKeyCredential
 */
public class MakeCredentialOptions implements Parcelable {
    /**
     * The {@link RelyingParty} Identifier, for the Relying Party this public key credential source is scoped to.
     */
    @NonNull final RelyingParty rp;

    /**
     * The {@link User} handle associated when this public key credential source was created. This item is nullable.
     */
    @NonNull final User user;

    /**
     * This member contains a challenge intended to be used for generating the newly created credential’s attestation object..
     */
    @NonNull final byte[] challenge;

    /**
     * WebAuthn Relying Parties may use {@link AttestationConveyancePreference} to specify their preference regarding attestation conveyance during credential generation.
     */
    AttestationConveyancePreference attestation = null;

    /**
     * ExcludeCredentialDescriptorList contains a list of known credentials.
     * An OPTIONAL list of PublicKeyCredentialDescriptor objects provided by the Relying Party with the intention that,
     * if any of these are known to the authenticator, it SHOULD NOT create a new credential.
     */
    List<byte[]> excludeList = null;

    /**
     * Authenticators' attachment modalities {@link AuthenticatorAttachment}
     */
    AuthenticatorAttachment attachment = null;

    /**
     * Default list of algorithms if nothing provided
     */
    @NonNull List<Integer> algorithms = Arrays.asList(
            EC2Algorithm.ES256.getAlgoValue(),
            EC2Algorithm.ES384.getAlgoValue(),
            EC2Algorithm.ES512.getAlgoValue(),
            RSAAlgorithm.RS256.getAlgoValue(),
            RSAAlgorithm.RS384.getAlgoValue(),
            RSAAlgorithm.RS512.getAlgoValue(),
            RSAAlgorithm.PS256.getAlgoValue(),
            RSAAlgorithm.PS384.getAlgoValue(),
            RSAAlgorithm.PS512.getAlgoValue());

    /**
     * This OPTIONAL member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
     * The value is treated as a hint, and MAY be overridden by the client.
     */
    long timeoutMs;

    /**
     *
     * @param rp This member contains data about the Relying Party responsible for the request. {@link RelyingParty}
     * @param user This member contains data about the user account for which the Relying Party is requesting attestation. {@link User}
     * @param challenge This member contains a challenge intended to be used for generating the newly created credential’s attestation object.
     */
    public MakeCredentialOptions(@NonNull RelyingParty rp, @NonNull User user, @NonNull byte[] challenge) {
        this.rp = rp;
        this.user = user;
        this.challenge = challenge;
    }

    /**
     * @param attestation Attestation Conveyance Preference {@link AttestationConveyancePreference}
     * @throws AttestationConveyancePreference.UnsupportedAttestationConveyancePreferenceException when provided string is not valid
     * @return this object
     */
    public MakeCredentialOptions attestation(@Nullable String attestation) throws AttestationConveyancePreference.UnsupportedAttestationConveyancePreferenceException {
        this.attestation = AttestationConveyancePreference.fromString(attestation);
        return this;
    }

    /**
     * @param credentialIds list of credentials to exclude
     * @return this object
     */
    public MakeCredentialOptions excludeCredentials(@Nullable List<byte[]> credentialIds) {
        this.excludeList = credentialIds;
        return this;
    }

    /**
     * @param attachment Authenticators' attachment modalities {@link AuthenticatorAttachment}
     * @return this object
     */
    public MakeCredentialOptions authenticatorAttachment(@Nullable AuthenticatorAttachment attachment) {
        this.attachment = attachment;
        return this;
    }

    /**
     * This member contains information about the desired properties of the credential to be created.
     * The sequence is ordered from most preferred to least preferred.
     * The client makes a best-effort to create the most preferred credential that it can.
     * @param algorithms A numeric identifier for the algorithm to be used to generate the key pair.
     *                   The algorithm identifiers are defined by the CBOR Object Signing and Encryption (COSE) registry:
     *                   <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">https://www.iana.org/assignments/cose/cose.xhtml#algorithms</a>
     *                   (e.g. -7 indicates the elliptic curve algorithm ECDSA with SHA-256).
     * @return this object
     */
    public MakeCredentialOptions algorithms(@NonNull List<Integer> algorithms) {
        this.algorithms = algorithms;
        return this;
    }

    /**
     * This OPTIONAL member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
     * The value is treated as a hint, and MAY be overridden by the client.
     * @param timeout A hint, given in milliseconds, for the time the script is willing to wait for the completion of the creation operation.
     * @return this object
     */
    public MakeCredentialOptions timeoutMs(long timeout) {
        this.timeoutMs = timeout;
        return this;
    }

    protected MakeCredentialOptions(Parcel in) {
        rp = in.readParcelable(RelyingParty.class.getClassLoader());
        user = in.readParcelable(User.class.getClassLoader());
        challenge = in.createByteArray();
        attestation = (AttestationConveyancePreference) in.readSerializable();
        attachment = (AuthenticatorAttachment) in.readSerializable();
        int nCredentials = in.readInt();
        if (nCredentials > 0) {
            excludeList = new ArrayList<>();
            for (byte i = 0; i < nCredentials; i++) {
                excludeList.add(in.createByteArray());
            }
        }
        algorithms = new ArrayList<>();
        for (int i = in.readInt(); i > 0; i--) {
            algorithms.add(in.readInt());
        }
        timeoutMs = in.readLong();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeParcelable(rp, flags);
        dest.writeParcelable(user, flags);
        dest.writeByteArray(challenge);
        dest.writeSerializable(attestation);
        dest.writeSerializable(attachment);
        if (excludeList == null || excludeList.isEmpty()) {
            dest.writeInt(0);
        } else {
            dest.writeInt(excludeList.size());
            for (byte[] credentialId : excludeList) {
                dest.writeByteArray(credentialId);
            }
        }
        dest.writeInt(algorithms.size());
        for (int algorithm : algorithms) {
            dest.writeInt(algorithm);
        }
        dest.writeLong(timeoutMs);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<MakeCredentialOptions> CREATOR = new Creator<MakeCredentialOptions>() {
        @Override
        public MakeCredentialOptions createFromParcel(Parcel in) {
            return new MakeCredentialOptions(in);
        }

        @Override
        public MakeCredentialOptions[] newArray(int size) {
            return new MakeCredentialOptions[size];
        }
    };
}

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

package com.yubico.yubikit.demo.fido.communication

import com.squareup.moshi.Json

data class RegisterBeginRequest(
        @Json(name="authenticatorAttachment")
        val authenticatorAttachment: String
)

data class RegisterFinishRequest(
        @Json(name="requestId")
        val requestId: String,
        @Json(name="attestation")
        val attestation: Attestation
)

data class RegisterBeginResponse(
        @Json(name="data")
        val data: RegisterBeginData,
        @Json(name="status")
        val status: String
)

data class RegisterFinishResponse(
        @Json(name="data")
        val data: RegisterFinishData,
        @Json(name="status")
        val status: String
)

data class Attestation(
        /**
         * An ArrayBuffer containing authenticator data and an attestation statement for a newly-created key pair.
         */
        @Json(name="attestationObject")
        var attestationObject: ByteArray,

        /**
         * Client data for the authentication, such as origin and challenge. The clientDataJSON property is inherited from the AuthenticatorResponse.
         */
        @Json(name="clientDataJSON")
        var clientDataJSON: ByteArray
) {
        override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (javaClass != other?.javaClass) return false

                other as Attestation

                if (!attestationObject.contentEquals(other.attestationObject)) return false
                if (!clientDataJSON.contentEquals(other.clientDataJSON)) return false

                return true
        }

        override fun hashCode(): Int {
                var result = attestationObject.contentHashCode()
                result = 31 * result + clientDataJSON.contentHashCode()
                return result
        }
}

data class RegisterBeginData(
        @Json(name="publicKey")
        val publicKey: PublicKey,
        @Json(name="requestId")
        val requestId: String
)

/**
 * Array whose elements are objects describing the desired features of the credential to be created.
 * These objects define the type of public-key and the algorithm used for cryptographic signature operations.
 */
data class PubKeyCredParam(
        @Json(name="alg")
        val alg: Int,
        @Json(name="type")
        val type: String
)

/**
 * Object describing the relying party which requested the credential creation
 * That communication class is representing data that stored in class {@link com.yubico.yubikit.fido.RelyingParty} of Yubikit library
 */
data class Rp(
        @Json(name="id")
        val id: String,
        @Json(name="name")
        val name: String
)

/**
 * An object giving criteria to filter out the authenticators to be used for the creation operation.
 */
data class AuthenticatorSelection(
        @Json(name="authenticatorAttachment")
        val authenticatorAttachment: String,
        @Json(name="requireResidentKey")
        val requireResidentKey: Boolean,
        @Json(name="userVerification")
        val userVerification: String
)

data class PublicKey(
        /**
         * This is a string whose value indicates the preference regarding the attestation transport, between the authenticator, the client and the relying party.
         * The attestation is a mean for the relying party to verify the origin of the authenticator with an attestation certificate authority.
         * The information contained in the attestation may thus disclose some information about the user (e.g. which device they are using).
         */
        @Json(name="attestation")
        val attestation: String,

        /**
         * An object giving criteria to filter out the authenticators to be used for the creation operation.
         */
        @Json(name="authenticatorSelection")
        val authenticatorSelection: AuthenticatorSelection,

        /**
         * This is randomly generated then sent from the relying party's server.
         * This value (among other client data) will be signed by the authenticator,
         * using its private key, and must be sent back for verification to the server as part of {@see MakeCredentialResponse::getAttestationObject}.
         */
        @Json(name="challenge")
        val challenge: ByteArray,

        /**
         *  Array whose elements are descriptors for the public keys already existing for a given user.
         */
        @Json(name="excludeCredentials")
        val excludeCredentials: List<CredentialDescriptor>,

        /**
         * Array whose elements are objects describing the desired features of the credential to be created.
         */
        @Json(name="pubKeyCredParams")
        val pubKeyCredParams: List<PubKeyCredParam>,

        /**
         * Object describing the relying party which requested the credential creation
         */
        @Json(name="rp")
        val rp: Rp,

        /**
         * A hint, given in milliseconds, for the time the script is willing to wait for the completion of the creation operation.
         */
        @Json(name="timeout")
        val timeout: Long,

        /**
         * Object describing the user account for which the credentials are generated
         */
        @Json(name="user")
        val user: UserIdentity
) {
        override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (javaClass != other?.javaClass) return false

                other as PublicKey

                if (attestation != other.attestation) return false
                if (authenticatorSelection != other.authenticatorSelection) return false
                if (!challenge.contentEquals(other.challenge)) return false
                if (excludeCredentials != other.excludeCredentials) return false
                if (pubKeyCredParams != other.pubKeyCredParams) return false
                if (rp != other.rp) return false
                if (timeout != other.timeout) return false
                if (user != other.user) return false

                return true
        }

        override fun hashCode(): Int {
                var result = attestation.hashCode()
                result = 31 * result + authenticatorSelection.hashCode()
                result = 31 * result + challenge.contentHashCode()
                result = 31 * result + excludeCredentials.hashCode()
                result = 31 * result + pubKeyCredParams.hashCode()
                result = 31 * result + rp.hashCode()
                result = 31 * result + timeout.hashCode()
                result = 31 * result + user.hashCode()
                return result
        }
}

/**
 * excludeCredentials elements are descriptors for the public keys already existing for a given user.
 * This is provided by the relying party's server if it wants to prevent creation of new credentials for an existing user.
 */
data class CredentialDescriptor  (
        @Json(name="type")
        val type: String,
        @Json(name="id")
        val id: ByteArray) {
        override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (javaClass != other?.javaClass) return false

                other as CredentialDescriptor

                if (type != other.type) return false
                if (!id.contentEquals(other.id)) return false

                return true
        }

        override fun hashCode(): Int {
                var result = type.hashCode()
                result = 31 * result + id.contentHashCode()
                return result
        }
}

/**
 * That communication class is representing data that stored in class {@link com.yubico.yubikit.fido.User} of Yubikit library
 */
data class UserIdentity  (
        @Json(name="displayName")
        val displayName: String,
        @Json(name="name")
        val username: String,
        @Json(name="id")
        val id: ByteArray) {
        override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (javaClass != other?.javaClass) return false

                other as UserIdentity

                if (displayName != other.displayName) return false
                if (username != other.username) return false
                if (!id.contentEquals(other.id)) return false

                return true
        }

        override fun hashCode(): Int {
                var result = displayName.hashCode()
                result = 31 * result + username.hashCode()
                result = 31 * result + id.contentHashCode()
                return result
        }
}

data class Device(
        @Json(name="name")
        val name: String,
        @Json(name="type")
        val type: String,
        @Json(name="url")
        val url: String?
)

data class RegisterFinishData(
        @Json(name="device")
        val device: Device,
        @Json(name="deviceId")
        val deviceId: String,
        @Json(name="issuer")
        val issuer: String?,
        @Json(name="type")
        val type: String
)
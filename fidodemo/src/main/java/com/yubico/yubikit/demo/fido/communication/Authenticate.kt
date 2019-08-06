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

data class AuthBeginRequest (
        @Json(name="uuid")
        val uuid: String?,
        @Json(name="namespace")
        val namespace: String,
        @Json(name="crossPlatformOnly")
        val crossPlatformOnly: Boolean = false
)

data class AuthBeginResponse (
        @Json(name="data")
    val data: AuthBeginData,
        @Json(name="status")
    val status: String
)

data class AuthFinishRequest(
        @Json(name="requestId")
        val requestId: String,
        @Json(name="assertion")
        val assertion: Assertion,
        @Json(name="uuid")
        val uuid: String,
        @Json(name="namespace")
        val namespace: String
)

data class AuthFinishResponse(
        @Json(name="data")
        val data: AuthFinishData,
        @Json(name="status")
        val status: String
)

data class AuthFinishData(
        @Json(name="user")
        val user: User,
        @Json(name="deviceId")
        val deviceId: String,
        @Json(name="authenticatorAttachment")
        val authenticatorAttachment : String? = null
)

data class AuthBeginData(
        @Json(name="publicKey")
        val publicKey: AuthPublicKey,
        @Json(name="requestId")
        val requestId: String
)

data class AuthPublicKey(
        @Json(name="rpId")
        val rpId: String,
        @Json(name="timeout")
        val timeout: Long,
        @Json(name="challenge")
        val challenge: String,
        @Json(name="allowCredentials")
        val allowCredentials: List<AllowCredential>,
        @Json(name="userVerification")
        val userVerification: String
)

data class AllowCredential (
        @Json(name="id")
        val id: String,
        @Json(name="type")
        val type: String
)

data class Assertion(
        /**
         * A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
         */
        @Json(name="credentialId")
        val credentialId: ByteArray,

        /**
         * An ArrayBuffer containing information from the authenticator such as the Relying Party ID Hash (rpIdHash),
         * a signature counter, test of user presence and user verification flags, and any extensions processed by the authenticator.
         */
        @Json(name="authenticatorData")
        val authenticatorData: ByteArray,

        /**
         * The client data for the authentication, such as origin and challenge.
         */
        @Json(name="clientDataJSON")
        val clientDataJSON: ByteArray,

        /**
         * An assertion signature over Assertion.authenticatorData and Assertion.clientDataJSON.
         * The assertion signature is created with the private key of keypair that was created during the MakeCredentials call and
         * verified using the public key of that same keypair.
         */
        @Json(name="signature")
        val signature: ByteArray,

        /**
         * An ArrayBuffer containing an opaque user identifier.
         */
        @Json(name="userHandle")
        val userHandle: ByteArray?
) {
        override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (javaClass != other?.javaClass) return false

                other as Assertion

                if (!credentialId.contentEquals(other.credentialId)) return false
                if (!authenticatorData.contentEquals(other.authenticatorData)) return false
                if (!clientDataJSON.contentEquals(other.clientDataJSON)) return false
                if (!signature.contentEquals(other.signature)) return false
                if (userHandle != null) {
                        if (other.userHandle == null) return false
                        if (!userHandle.contentEquals(other.userHandle)) return false
                } else if (other.userHandle != null) return false

                return true
        }

        override fun hashCode(): Int {
                var result = credentialId.contentHashCode()
                result = 31 * result + authenticatorData.contentHashCode()
                result = 31 * result + clientDataJSON.contentHashCode()
                result = 31 * result + signature.contentHashCode()
                result = 31 * result + (userHandle?.contentHashCode() ?: 0)
                return result
        }
}
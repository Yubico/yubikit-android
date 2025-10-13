/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.fido.android

import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.android.util.toMap
import com.yubico.yubikit.fido.client.ClientError
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions
import org.json.JSONObject

class FidoClientService(private val viewModel: MainViewModel = MainViewModel()) {

    private val commandState = CommandState()

    enum class Operation {
        MAKE_CREDENTIAL,
        GET_ASSERTION
    }

    fun cancelOngoingOperation() = commandState.cancel()

    suspend fun performOperation(
        pin: String?,
        operation: Operation,
        rpId: String,
        clientDataHash: ByteArray?,
        request: String,
        onConnection: () -> Unit
    ): Result<PublicKeyCredential> {
        return when (operation) {
            Operation.MAKE_CREDENTIAL -> makeCredential(
                pin,
                rpId,
                clientDataHash,
                request,
                onConnection
            )

            Operation.GET_ASSERTION -> getAssertion(
                pin,
                rpId,
                clientDataHash,
                request,
                onConnection
            )
        }
    }

    private fun buildClientData(
        type: String, origin: String, challenge: String
    ): ByteArray {
        return """
            {
                "type": "$type",
                "challenge": "$challenge",
                "origin": "$origin"
            }
        """.trimIndent().toByteArray()
    }

    private suspend fun makeCredential(
        pin: String?,
        rpId: String,
        clientDataHash: ByteArray?,
        request: String,
        onConnection: () -> Unit
    ): Result<PublicKeyCredential> =
        viewModel.useWebAuthn { client ->
            onConnection()

            if (client.isPinSupported && !client.isPinConfigured) {
                // there is not PIN set on the key, we deliberately don't allow this
                throw ClientError(
                    ClientError.Code.BAD_REQUEST,
                    CtapException(CtapException.ERR_PIN_NOT_SET)
                )
            }

            val requestJson = JSONObject(request).toMap()

            val publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions.fromMap(
                JSONObject(request).toMap()
            )

            if (clientDataHash != null) {
                client.makeCredentialWithHash(
                    clientDataHash,
                    publicKeyCredentialCreationOptions,
                    rpId.removePrefix("https://"), // TODO reason about this
                    pin?.toCharArray(),
                    null,
                    commandState
                )
            } else {
                client.makeCredential(
                    buildClientData(
                        "webauthn.create",
                        rpId,
                        requestJson["challenge"] as String
                    ),
                    publicKeyCredentialCreationOptions,
                    rpId.removePrefix("https://"), // TODO reason about this
                    pin?.toCharArray(),
                    null,
                    commandState
                )
            }
        }

    private suspend fun getAssertion(
        pin: String?,
        rpId: String,
        clientDataHash: ByteArray?,
        request: String,
        onConnection: () -> Unit
    ): Result<PublicKeyCredential> =
        viewModel.useWebAuthn { client ->
            onConnection()

            val requestJson = JSONObject(request).toMap()

            val clientData = buildClientData(
                "webauthn.get",
                rpId,
                requestJson["challenge"] as String
            )

            val publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions.fromMap(
                JSONObject(request).toMap()
            )

            if (clientDataHash != null) {
                client.getAssertionWithHash(
                    clientDataHash,
                    publicKeyCredentialRequestOptions,
                    rpId.removePrefix("https://"), // TODO reason about this
                    pin?.toCharArray(),
                    commandState,
                )
            } else {
                client.getAssertion(
                    clientData,
                    publicKeyCredentialRequestOptions,
                    rpId.removePrefix("https://"), // TODO reason about this
                    pin?.toCharArray(),
                    commandState,
                )
            }
        }

    suspend fun createPin(
        pin: String,
    ) = viewModel.useWebAuthn { client ->
        client.setPin(pin.toCharArray())
    }

}


/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit.fido.android.internal

import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.android.Origin
import com.yubico.yubikit.fido.android.internal.util.toMap
import com.yubico.yubikit.fido.client.ClientError
import com.yubico.yubikit.fido.client.Ctap2Client
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions
import org.json.JSONObject

internal class FidoClientService(private val viewModel: MainViewModel = MainViewModel()) {

    internal enum class Operation {
        MAKE_CREDENTIAL,
        GET_ASSERTION,
    }

    private val commandState = CommandState()

    internal fun cancelOngoingOperation() = commandState.cancel()

    internal suspend fun performOperation(
        pin: CharArray?,
        operation: Operation,
        origin: Origin,
        clientDataHash: ByteArray?,
        request: String,
        onConnection: () -> Unit,
    ): Result<PublicKeyCredential> {
        return when (operation) {
            Operation.MAKE_CREDENTIAL ->
                makeCredential(
                    pin,
                    origin,
                    clientDataHash,
                    request,
                    onConnection,
                )

            Operation.GET_ASSERTION ->
                getAssertion(
                    pin,
                    origin,
                    clientDataHash,
                    request,
                    onConnection,
                )
        }
    }

    private fun buildClientData(
        type: String,
        origin: String,
        challenge: String,
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
        pin: CharArray?,
        origin: Origin,
        clientDataHash: ByteArray?,
        request: String,
        onConnection: () -> Unit,
    ): Result<PublicKeyCredential> =
        viewModel.useWebAuthn { client ->
            onConnection()

            (client as? Ctap2Client)?.run {
                if (this.session.cachedInfo.forcePinChange) {
                    // there is PIN set, but it must be changed first
                    throw ClientError(
                        ClientError.Code.BAD_REQUEST,
                        CtapException(CtapException.ERR_PIN_POLICY_VIOLATION),
                    )
                }

                if (isPinSupported && !isPinConfigured) {
                    // there is not PIN set on the key, we deliberately don't allow this
                    throw ClientError(
                        ClientError.Code.BAD_REQUEST,
                        CtapException(CtapException.ERR_PIN_NOT_SET),
                    )
                }
            }

            val requestJson = JSONObject(request).toMap()

            val publicKeyCredentialCreationOptions =
                PublicKeyCredentialCreationOptions.fromMap(
                    JSONObject(request).toMap(),
                )

            val clientData =
                clientDataHash?.let { ClientDataProvider.fromHash(it) }
                    ?: ClientDataProvider.fromClientDataJson(
                        buildClientData(
                            "webauthn.create",
                            origin.resolved,
                            requestJson["challenge"] as String,
                        ),
                    )

            client.makeCredential(
                clientData,
                publicKeyCredentialCreationOptions,
                origin.effectiveDomain,
                pin,
                null,
                commandState,
            )
        }

    private suspend fun getAssertion(
        pin: CharArray?,
        origin: Origin,
        clientDataHash: ByteArray?,
        request: String,
        onConnection: () -> Unit,
    ): Result<PublicKeyCredential> =
        viewModel.useWebAuthn { client ->
            onConnection()

            (client as? Ctap2Client)?.run {
                if (this.session.cachedInfo.forcePinChange) {
                    // there is PIN set, but it must be changed first
                    throw ClientError(
                        ClientError.Code.BAD_REQUEST,
                        CtapException(CtapException.ERR_PIN_POLICY_VIOLATION),
                    )
                }
            }

            val requestJson = JSONObject(request).toMap()

            val clientData =
                clientDataHash?.let { ClientDataProvider.fromHash(it) }
                    ?: ClientDataProvider.fromClientDataJson(
                        buildClientData(
                            "webauthn.get",
                            origin.resolved,
                            requestJson["challenge"] as String,
                        ),
                    )

            val publicKeyCredentialRequestOptions =
                PublicKeyCredentialRequestOptions.fromMap(
                    JSONObject(request).toMap(),
                )

            client.getAssertion(
                clientData,
                publicKeyCredentialRequestOptions,
                origin.effectiveDomain,
                pin,
                commandState,
            )
        }

    internal suspend fun createPin(pin: CharArray): Result<Unit> =
        viewModel.useWebAuthn { client ->
            (client as? Ctap2Client)?.setPin(pin)
        }

    internal suspend fun changePin(
        currentPin: CharArray,
        newPin: CharArray,
    ): Result<Unit> = viewModel.useWebAuthn { client ->
        (client as? Ctap2Client)?.changePin(currentPin, newPin)
    }
}

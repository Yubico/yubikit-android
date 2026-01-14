/*
 * Copyright (C) 2025-2026 Yubico.
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

package com.yubico.yubikit.fido.android.providerservice

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialCustomException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCustomException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.coroutineScope
import com.yubico.yubikit.fido.android.YubiKitFidoClient
import com.yubico.yubikit.fido.android.config.YubiKitFidoConfigManager
import com.yubico.yubikit.fido.android.providerservice.YubiKitProviderService.Companion.allowList
import com.yubico.yubikit.fido.client.extensions.CredBlobExtension
import com.yubico.yubikit.fido.client.extensions.CredPropsExtension
import com.yubico.yubikit.fido.client.extensions.CredProtectExtension
import com.yubico.yubikit.fido.client.extensions.Extension
import com.yubico.yubikit.fido.client.extensions.HmacSecretExtension
import com.yubico.yubikit.fido.client.extensions.LargeBlobExtension
import com.yubico.yubikit.fido.client.extensions.MinPinLengthExtension
import com.yubico.yubikit.fido.client.extensions.SignExtension
import kotlinx.coroutines.launch
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.JSONObject
import org.slf4j.LoggerFactory
import java.security.Security
import kotlin.coroutines.cancellation.CancellationException

class YubiKitFido2ProviderActivity : ComponentActivity() {
    private val yubiKitFidoClient by lazy {
        YubiKitFidoClient(this, extensions = defaultExtensions)
    }

    private val defaultExtensions: List<Extension> =
        listOf(
            CredPropsExtension(),
            CredBlobExtension(),
            CredProtectExtension(),
            HmacSecretExtension(),
            MinPinLengthExtension(),
            LargeBlobExtension(),
            // ThirdPartyPaymentExtension(),
            SignExtension(),
        )

    private val logger = LoggerFactory.getLogger(YubiKitFido2ProviderActivity::class.java)

    override fun onCreate(savedInstanceState: Bundle?) {
        // Load config from preferences and update ClientConfiguration
        ProviderServicePreferences.loadConfiguration(this).also {
            YubiKitFidoConfigManager.replace(it)
        }
        super.onCreate(savedInstanceState)

        Security.removeProvider("BC")
        Security.insertProviderAt(BouncyCastleProvider(), 1)

        handleCreateCredential() || handleGetCredential() || throw IllegalStateException("Invalid invocation.")
    }

    private fun handleCreateCredential(): Boolean {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val createPublicKeyCredentialRequest =
            request
                ?.callingRequest as? CreatePublicKeyCredentialRequest
                ?: return false
        val origin =
            extractOrigin(
                request.callingAppInfo,
                createPublicKeyCredentialRequest.requestJson,
            ).getOrElse { return reportCreateCredentialError(it) }

        launchCredentialFlow(
            action = {
                val response =
                    yubiKitFidoClient.makeCredential(
                        origin.removeSuffix("/"),
                        createPublicKeyCredentialRequest.requestJson,
                        createPublicKeyCredentialRequest.clientDataHash?.toHexString(),
                    ).getOrThrow()
                logger.debug("CreatePublicKeyCredentialResponse: {}", response)
                PendingIntentHandler.setCreateCredentialResponse(
                    intent,
                    CreatePublicKeyCredentialResponse(response),
                )
            },
            onCancel = {
                logger.debug("User cancelled CreateCredential")
                PendingIntentHandler.setCreateCredentialException(
                    intent,
                    CreateCredentialCancellationException(),
                )
            },
        )
        return true
    }

    private fun handleGetCredential(): Boolean {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val getPublicKeyCredentialOption =
            request
                ?.credentialOptions?.getOrNull(0) as? GetPublicKeyCredentialOption
                ?: return false
        val origin =
            extractOrigin(
                request.callingAppInfo,
                getPublicKeyCredentialOption.requestJson,
            ).getOrElse { return reportGetCredentialError(it) }

        launchCredentialFlow(
            action = {
                val response =
                    yubiKitFidoClient.getAssertion(
                        origin.removeSuffix("/"),
                        getPublicKeyCredentialOption.requestJson,
                        getPublicKeyCredentialOption.clientDataHash?.toHexString(),
                    ).getOrThrow()

                logger.debug("GetCredentialResponse: {}", response)
                PendingIntentHandler.setGetCredentialResponse(
                    intent,
                    GetCredentialResponse(PublicKeyCredential(response)),
                )
            },
            onCancel = {
                logger.debug("User cancelled GetCredential")
                PendingIntentHandler.setGetCredentialException(
                    intent,
                    GetCredentialCancellationException(),
                )
            },
        )
        return true
    }

    private fun launchCredentialFlow(
        action: suspend () -> Unit,
        onCancel: () -> Unit,
    ) = lifecycle.coroutineScope.launch {
        try {
            action()
        } catch (_: CancellationException) {
            onCancel()
        } finally {
            setResult(RESULT_OK, intent)
            finish()
        }
    }

    private fun reportCreateCredentialError(error: Throwable): Boolean {
        logger.error("CreateCredential failed: ", error)
        PendingIntentHandler.setCreateCredentialException(
            intent,
            CreateCredentialCustomException(
                PublicKeyCredential.TYPE_PUBLIC_KEY_CREDENTIAL,
                "CreateCredential failed: ${error::class.simpleName}: ${error.message ?: "Unknown error"}",
            ),
        )
        setResult(RESULT_OK, intent)
        finish()
        return false
    }

    private fun reportGetCredentialError(error: Throwable): Boolean {
        logger.error("GetCredential failed: ", error)
        PendingIntentHandler.setGetCredentialException(
            intent,
            GetCredentialCustomException(
                PublicKeyCredential.TYPE_PUBLIC_KEY_CREDENTIAL,
                "GetCredential failed: ${error::class.simpleName}: ${error.message ?: "Unknown error"}",
            ),
        )
        setResult(RESULT_OK, intent)
        finish()
        return false
    }

    private fun extractOrigin(
        appInfo: CallingAppInfo,
        requestJson: String,
    ): Result<String> {
        return runCatching {
            if (appInfo.isOriginPopulated()) {
                // getOrigin might return null, so handle it
                appInfo.getOrigin(allowList)
                    ?: throw NullPointerException("Origin is null from allowList")
            } else {
                val rpId = "rpId"
                val rp = "rp"
                val id = "id"

                val request = JSONObject(requestJson)
                "https://" +
                    if (request.has(rpId)) {
                        request.getString(rpId)
                    } else if (request.has(rp)) {
                        request.getJSONObject(rp).getString(id)
                    } else {
                        throw IllegalArgumentException("Failed to extract origin")
                    }
            }
        }
    }
}

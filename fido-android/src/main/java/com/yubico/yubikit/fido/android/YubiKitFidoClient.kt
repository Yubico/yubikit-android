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

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContract
import androidx.compose.runtime.Composable
import androidx.fragment.app.Fragment
import com.yubico.yubikit.fido.client.extensions.Extension
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class YubiKitFidoClient {
    private data class FidoRequest(
        val operation: FidoClientService.Operation,
        val rpId: String,
        val clientDataHash: String?,
        val request: String,
    )

    private var currentContinuation: CancellableContinuation<Result<String>>? = null
    private var launcher: ActivityResultLauncher<FidoRequest>

    companion object {
        var extensions: List<Extension>? = emptyList()
    }

    constructor(fragment: Fragment, extensions: List<Extension>? = null) : this(
        fragment,
        extensions,
        null,
    )

    constructor(
        fragment: Fragment,
        extensions: List<Extension>? = null,
        theme: (@Composable (content: @Composable () -> Unit) -> Unit)? = null,
    ) {
        YubiKitFidoActivity.setTheme(theme)
        launcher =
            fragment.registerForActivityResult(FidoActivityResultContract()) { result ->
                handleResult(result)
            }
        Companion.extensions = extensions
    }

    constructor(activity: ComponentActivity, extensions: List<Extension>? = null) : this(
        activity,
        extensions,
        null,
    )

    constructor(
        activity: ComponentActivity,
        extensions: List<Extension>? = null,
        theme: (@Composable (content: @Composable () -> Unit) -> Unit)? = null,
    ) {
        YubiKitFidoActivity.setTheme(theme)
        launcher =
            activity.registerForActivityResult(FidoActivityResultContract()) { result ->
                handleResult(result)
            }
        Companion.extensions = extensions
    }

    private fun handleResult(result: Result<String>) {
        currentContinuation?.let { continuation ->
            result
                .onSuccess { continuation.resume(result) }
                .onFailure { continuation.resumeWithException(it) }
            currentContinuation = null
        }
    }

    private suspend fun execute(
        type: FidoClientService.Operation,
        rpId: String,
        clientDataHash: String?,
        request: String,
    ): Result<String> =
        suspendCancellableCoroutine { continuation ->
            if (currentContinuation != null) {
                continuation.resumeWithException(IllegalStateException("A FIDO request is already in progress"))
                return@suspendCancellableCoroutine
            }
            currentContinuation = continuation
            launcher.launch(FidoRequest(type, rpId, clientDataHash, request))
            continuation.invokeOnCancellation {
                if (it is CancellationException) {
                    currentContinuation = null
                }
            }
        }

    suspend fun makeCredential(
        rpId: String,
        request: String,
        clientDataHash: String?,
    ): Result<String> {
        return execute(FidoClientService.Operation.MAKE_CREDENTIAL, rpId, clientDataHash, request)
    }

    suspend fun getAssertion(
        rpId: String,
        request: String,
        clientDataHash: String?,
    ): Result<String> {
        return execute(FidoClientService.Operation.GET_ASSERTION, rpId, clientDataHash, request)
    }

    private class FidoActivityResultContract :
        ActivityResultContract<FidoRequest, Result<String>>() {
        override fun createIntent(
            context: Context,
            input: FidoRequest,
        ): Intent {
            return Intent(context, YubiKitFidoActivity::class.java).apply {
                putExtra("type", input.operation.ordinal)
                putExtra("rpId", input.rpId)
                putExtra("clientDataHash", input.clientDataHash)
                putExtra("request", input.request)
            }
        }

        override fun parseResult(
            resultCode: Int,
            intent: Intent?,
        ): Result<String> =
            when {
                resultCode == Activity.RESULT_OK && intent != null ->
                    intent.getStringExtra("credential")?.let { credentialJson ->
                        Result.success(credentialJson)
                    }
                        ?: Result.failure(IllegalStateException("Credential missing in Intent result"))

                resultCode == Activity.RESULT_CANCELED ->
                    Result.failure(CancellationException("User cancelled FIDO operation"))

                resultCode == RESULT_KEY_REMOVED ->
                    Result.failure(CancellationException("Key was removed"))

                else -> Result.failure(IllegalStateException("Unknown error occurred (resultCode: $resultCode)"))
            }
    }
}

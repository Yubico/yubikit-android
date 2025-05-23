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
import com.yubico.yubikit.fido.android.YubiKitFidoActivity.Companion.toMap
import com.yubico.yubikit.fido.client.extensions.Extension
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import kotlin.coroutines.resume

class YubiKitFidoClient {
    private data class FidoRequest(
        val operation: FidoClientService.Operation,
        val rpId: String,
        val request: String
    )

    private var currentContinuation: CancellableContinuation<Result<PublicKeyCredential>>? = null
    private val launcher: ActivityResultLauncher<FidoRequest>

    companion object {
        var extensions: List<Extension>? = null
    }

    constructor(
        fragment: Fragment,
        extensions: List<Extension>? = null
    ) : this(
        fragment,
        extensions,
        null
    )

    constructor(
        fragment: Fragment,
        extensions: List<Extension>? = null,
        theme: (@Composable (content: @Composable () -> Unit) -> Unit)? = null
    ) {
        YubiKitFidoActivity.ThemeManager.setTheme(theme)
        launcher = fragment.registerForActivityResult(
            FidoActivityResultContract()
        ) { result ->
            val continuation = currentContinuation
            if (continuation != null) {
                continuation.resume(result)
                currentContinuation = null
            }
        }
        Companion.extensions = extensions
    }

    constructor(
        activity: ComponentActivity,
        extensions: List<Extension>? = null,
        theme: (@Composable (content: @Composable () -> Unit) -> Unit)? = null
    ) {
        YubiKitFidoActivity.ThemeManager.setTheme(theme)
        launcher = activity.registerForActivityResult(
            FidoActivityResultContract()
        ) { result ->
            val continuation = currentContinuation
            if (continuation != null) {
                continuation.resume(result)
                currentContinuation = null
            }
        }
        Companion.extensions = extensions
    }

    private suspend fun execute(
        type: FidoClientService.Operation,
        rpId: String,
        request: String
    ): Result<PublicKeyCredential> {
        return suspendCancellableCoroutine { continuation ->
            currentContinuation = continuation
            launcher.launch(FidoRequest(type, rpId, request))
            continuation.invokeOnCancellation {
                continuation.cancel(CancellationException())
            }
        }
    }

    suspend fun makeCredential(rpId: String, request: String): Result<PublicKeyCredential> {
        return execute(FidoClientService.Operation.MAKE_CREDENTIAL, rpId, request)
    }

    suspend fun getAssertion(rpId: String, request: String): Result<PublicKeyCredential> {
        return execute(FidoClientService.Operation.GET_ASSERTION, rpId, request)
    }

    private class FidoActivityResultContract :
        ActivityResultContract<FidoRequest, Result<PublicKeyCredential>>() {

        override fun createIntent(context: Context, input: FidoRequest): Intent {
            return Intent(context, YubiKitFidoActivity::class.java).apply {
                putExtra("type", input.operation.ordinal)
                putExtra("rpId", input.rpId)
                putExtra("request", input.request)
            }
        }

        override fun parseResult(resultCode: Int, intent: Intent?): Result<PublicKeyCredential> {
            return if (resultCode == Activity.RESULT_OK && intent != null) {
                intent.getStringExtra("credential")?.let { credentialJson ->
                    val credential = PublicKeyCredential.fromMap(JSONObject(credentialJson).toMap())
                    Result.success(credential)
                } ?: run {
                    Result.failure(IllegalStateException())
                }
            } else {
                Result.failure(IllegalStateException())
            }
        }
    }
}

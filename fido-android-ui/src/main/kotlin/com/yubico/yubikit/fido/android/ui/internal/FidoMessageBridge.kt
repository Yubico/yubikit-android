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

package com.yubico.yubikit.fido.android.ui.internal

import android.annotation.SuppressLint
import android.net.Uri
import android.webkit.WebView
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import com.yubico.yubikit.fido.android.ui.FidoClient
import com.yubico.yubikit.fido.android.ui.Origin
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.json.JSONObject
import org.slf4j.LoggerFactory

/**
 * WebMessage-based bridge for FIDO WebAuthn operations in a WebView.
 *
 * Registered via [WebViewCompat.addWebMessageListener], this bridge receives messages
 * from JavaScript through `postMessage()` with per-message origin verification and
 * frame isolation provided by the AndroidX WebKit API.
 *
 * Unlike [android.webkit.WebView.addJavascriptInterface], this approach:
 * - Provides the `sourceOrigin` of each message, preventing origin-attribution attacks
 * - Reports whether the message came from the main frame, enforcing iframe rejection
 * - Provides a [JavaScriptReplyProxy] for sending responses back to the originating frame only
 */
@SuppressLint("RequiresFeature") // Feature check is performed in FidoWebViewSupportImpl.enable()
internal class FidoMessageBridge(
    private val coroutineScope: CoroutineScope,
    private val fidoClient: FidoClient,
) : WebViewCompat.WebMessageListener {

    companion object {
        private val logger = LoggerFactory.getLogger(FidoMessageBridge::class.java)

        /** The JS-accessible object name registered with [WebViewCompat.addWebMessageListener]. */
        const val JS_BRIDGE_NAME = "__ykfido__"

        // JSON protocol keys — shared contract with fido.js
        private const val KEY_METHOD = "method"
        private const val KEY_PROMISE_UUID = "promiseUuid"
        private const val KEY_OPTIONS = "options"
        private const val KEY_PUBLIC_KEY = "publicKey"
        private const val KEY_TYPE = "type"
        private const val KEY_RESULT = "result"
        private const val KEY_MESSAGE = "message"

        // Protocol values
        private const val TYPE_RESOLVE = "resolve"
        private const val TYPE_REJECT = "reject"
        private const val METHOD_CREATE = "create"
        private const val METHOD_GET = "get"
    }

    override fun onPostMessage(
        view: WebView,
        message: WebMessageCompat,
        sourceOrigin: Uri,
        isMainFrame: Boolean,
        replyProxy: JavaScriptReplyProxy,
    ) {
        val data = message.data

        // Best-effort parse so that early-rejection paths can echo back
        // the promiseUuid and let the JS side reject the pending Promise.
        val json = try {
            if (!data.isNullOrEmpty()) JSONObject(data) else null
        } catch (_: Exception) {
            null
        }
        val earlyUuid = json?.optString(KEY_PROMISE_UUID, "")?.ifEmpty { null }

        // Reject sub-frame requests — only the top-level page may use the bridge
        if (!isMainFrame) {
            logger.warn("Rejected FIDO request from sub-frame")
            replyProxy.postMessage(
                errorResponseJson(
                    promiseUuid = earlyUuid,
                    message = "WebAuthn is not supported in sub-frames",
                ),
            )
            return
        }

        // Reject non-HTTPS origins or origins with missing/invalid host
        val scheme = sourceOrigin.scheme
        if (scheme == null || !scheme.equals("https", ignoreCase = true)) {
            logger.warn("Rejected FIDO request from non-HTTPS origin (scheme: {})", scheme)
            replyProxy.postMessage(
                errorResponseJson(
                    promiseUuid = earlyUuid,
                    message = "WebAuthn requires an HTTPS origin",
                ),
            )
            return
        }

        val host = sourceOrigin.host
        if (host.isNullOrEmpty()) {
            logger.warn("Rejected FIDO request with missing host")
            replyProxy.postMessage(
                errorResponseJson(
                    promiseUuid = earlyUuid,
                    message = "WebAuthn requires an origin with a valid host",
                ),
            )
            return
        }

        if (data.isNullOrEmpty()) {
            logger.warn("Received empty WebMessage, ignoring")
            return
        }

        if (json == null) {
            logger.warn("Failed to parse WebMessage JSON")
            replyProxy.postMessage(
                errorResponseJson(promiseUuid = null, message = "Invalid message format"),
            )
            return
        }

        val method = json.optString(KEY_METHOD, "")
        val promiseUuid = earlyUuid ?: ""
        val options = json.optString(KEY_OPTIONS, "")

        if (method.isEmpty() || promiseUuid.isEmpty() || options.isEmpty()) {
            logger.warn(
                "WebMessage missing required fields (method={}, uuid={}, options={})",
                method.isNotEmpty(),
                promiseUuid.isNotEmpty(),
                options.isNotEmpty(),
            )
            replyProxy.postMessage(
                errorResponseJson(
                    promiseUuid = promiseUuid.ifEmpty { null },
                    message = "Missing required fields",
                ),
            )
            return
        }

        // Build the origin string (scheme://host[:port]) from the verified sourceOrigin
        val origin = buildOriginString(sourceOrigin)

        logger.trace("{}({})", method, promiseUuid)

        coroutineScope.launch {
            try {
                val mappedOptions = JSONObject(options)
                val publicKey = mappedOptions.optJSONObject(KEY_PUBLIC_KEY)
                val requestJson = publicKey?.toString() ?: mappedOptions.toString()

                val result = when (method) {
                    METHOD_CREATE -> {
                        fidoClient.makeCredential(
                            Origin(origin),
                            requestJson,
                            null,
                        ).getOrThrow()
                    }

                    METHOD_GET -> {
                        fidoClient.getAssertion(
                            Origin(origin),
                            requestJson,
                            null,
                        ).getOrThrow()
                    }

                    else -> throw IllegalArgumentException("Unknown method")
                }

                logger.debug("FIDO operation succeeded")
                replyProxy.postMessage(successResponseJson(promiseUuid, result))
            } catch (t: Throwable) {
                logger.error("FIDO operation failed", t)
                replyProxy.postMessage(
                    errorResponseJson(promiseUuid = promiseUuid, message = "The operation failed"),
                )
            }
        }
    }

    /**
     * Builds an origin string (scheme://host[:port]) from a [Uri].
     *
     * Callers must ensure that [Uri.getScheme] and [Uri.getHost] are non-null
     * before invoking this method (validated earlier in [onPostMessage]).
     */
    private fun buildOriginString(uri: Uri): String {
        val scheme = requireNotNull(uri.scheme) { "scheme must not be null" }
        val host = requireNotNull(uri.host) { "host must not be null" }
        val port = uri.port
        return if (port != -1) "$scheme://$host:$port" else "$scheme://$host"
    }

    /** Creates a JSON success response string for delivery back to JavaScript. */
    private fun successResponseJson(promiseUuid: String, result: String): String =
        JSONObject().apply {
            put(KEY_TYPE, TYPE_RESOLVE)
            put(KEY_PROMISE_UUID, promiseUuid)
            put(KEY_RESULT, JSONObject(result))
        }.toString()

    /** Creates a JSON error response string for delivery back to JavaScript. */
    private fun errorResponseJson(promiseUuid: String?, message: String): String =
        JSONObject().apply {
            put(KEY_TYPE, TYPE_REJECT)
            if (promiseUuid != null) {
                put(KEY_PROMISE_UUID, promiseUuid)
            }
            put(KEY_MESSAGE, message)
        }.toString()
}

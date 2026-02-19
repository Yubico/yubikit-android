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
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.core.net.toUri
import com.yubico.yubikit.fido.android.ui.FidoClient
import com.yubico.yubikit.fido.android.ui.Origin
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.json.JSONObject
import org.slf4j.LoggerFactory

/**
 * JavaScript bridge injected into the WebView via [android.webkit.WebView.addJavascriptInterface].
 *
 * The injected JavaScript overrides `navigator.credentials.create()` and
 * `navigator.credentials.get()` to call methods on this bridge. Results are delivered
 * back to JavaScript via `__resolve__` / `__reject__` callbacks evaluated through
 * [WebView.evaluateJavascript].
 */
internal class FidoJsBridge(
    private val webView: WebView,
    private val coroutineScope: CoroutineScope,
    private val fidoClient: FidoClient,
) {
    companion object {
        const val BRIDGE_NAME = "__yubikit_fido_bridge__"
        private val logger = LoggerFactory.getLogger(FidoJsBridge::class.java)
    }

    /** Current page origin (scheme://host[:port]), updated on each page load. */
    @Volatile
    var currentOrigin: String? = null

    /**
     * Extracts the origin (scheme://host[:port]) from a full URL.
     * This matches the format that [androidx.webkit.WebViewCompat.WebMessageListener]
     * provides as `sourceOrigin`.
     */
    fun originFromUrl(url: String): String? {
        val uri = url.toUri()
        val scheme = uri.scheme ?: return null
        val host = uri.host ?: return null
        val port = uri.port
        return if (port != -1) "$scheme://$host:$port" else "$scheme://$host"
    }

    @JavascriptInterface
    @SuppressLint("unused")
    fun create(
        promiseUuid: String,
        options: String,
    ) {
        val origin = currentOrigin
        if (origin == null || !origin.startsWith("https://")) {
            rejectPromise(promiseUuid, "WebAuthn not permitted for current URL")
            return
        }

        logger.debug("create({}, ...) called", promiseUuid)

        coroutineScope.launch {
            try {
                val mappedOptions = JSONObject(options)
                val publicKey = mappedOptions.optJSONObject("publicKey")
                val requestJson = publicKey?.toString() ?: mappedOptions.toString()

                val result = fidoClient.makeCredential(
                    Origin(origin),
                    requestJson,
                    null,
                ).getOrThrow()

                logger.debug("makeCredential result: {}", result)
                resolvePromise(promiseUuid, result)
            } catch (t: Throwable) {
                logger.error("makeCredential failed", t)
                rejectPromise(promiseUuid, "Error: ${t.message}")
            }
        }
    }

    @JavascriptInterface
    @SuppressLint("unused")
    fun get(
        promiseUuid: String,
        options: String,
    ) {
        val origin = currentOrigin
        if (origin == null || !origin.startsWith("https://")) {
            rejectPromise(promiseUuid, "WebAuthn not permitted for current URL")
            return
        }

        logger.debug("get({}, ...) called", promiseUuid)

        coroutineScope.launch {
            try {
                val mappedOptions = JSONObject(options)
                val publicKey = mappedOptions.optJSONObject("publicKey")
                val requestJson = publicKey?.toString() ?: mappedOptions.toString()

                val result = fidoClient.getAssertion(
                    Origin(origin),
                    requestJson,
                    null,
                ).getOrThrow()

                logger.trace("getAssertion result: {}", result)
                resolvePromise(promiseUuid, result)
            } catch (t: Throwable) {
                logger.error("getAssertion failed", t)
                rejectPromise(promiseUuid, "Error: ${t.message}")
            }
        }
    }

    private fun resolvePromise(
        promiseUuid: String,
        result: String,
    ) {
        val escaped = escapeForJsString(
            JSONObject().apply {
                put("promiseUuid", promiseUuid)
                put("result", JSONObject(result))
            }
        )
        webView.post {
            webView.evaluateJavascript(
                """
                (function() {
                    var data = JSON.parse('$escaped');
                    ${BRIDGE_NAME}.__resolve__(data.promiseUuid, data.result);
                })();
                """.trimIndent(),
            ) {}
        }
    }

    private fun rejectPromise(
        promiseUuid: String,
        errorMessage: String,
    ) {
        val escaped = escapeForJsString(
            JSONObject().apply {
                put("promiseUuid", promiseUuid)
                put("message", errorMessage)
            }
        )
        webView.post {
            webView.evaluateJavascript(
                """
                (function() {
                    var error = JSON.parse('$escaped');
                    ${BRIDGE_NAME}.__reject__(error.promiseUuid, error.message);
                })();
                """.trimIndent(),
            ) {}
        }
    }

    /** Serializes a [JSONObject] and escapes it for safe embedding in a JS single-quoted string. */
    private fun escapeForJsString(json: JSONObject): String =
        json.toString()
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
}

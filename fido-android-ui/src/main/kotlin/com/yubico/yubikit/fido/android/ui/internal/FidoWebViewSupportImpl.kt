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
import android.graphics.Bitmap
import android.webkit.ConsoleMessage
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import com.yubico.yubikit.fido.android.ui.FidoClient
import kotlinx.coroutines.CoroutineScope
import org.slf4j.Logger
import org.slf4j.LoggerFactory

internal class FidoWebViewSupportImpl {
    companion object {
        private val logger: Logger = LoggerFactory.getLogger(FidoWebViewSupportImpl::class.java)
        private const val JS_SOURCE_TAG = "fido.js"

        /**
         * Enables the FIDO WebAuthn bridge on the given [WebView].
         *
         * Uses [WebViewCompat.addWebMessageListener] for per-message origin verification
         * and frame isolation. If the WebView implementation does not support
         * [WebViewFeature.WEB_MESSAGE_LISTENER], the bridge is **not** enabled and this
         * method returns `false` (fail-closed).
         *
         * @return `true` if the bridge was successfully enabled, `false` if the required
         *   WebView feature is not available.
         */
        @JvmStatic
        @SuppressLint("SetJavaScriptEnabled", "RequiresFeature")
        fun enable(
            webView: WebView,
            coroutineScope: CoroutineScope,
            fidoClient: FidoClient,
            webViewClient: WebViewClient,
        ): Boolean {
            if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
                logger.warn(
                    "WebView does not support WEB_MESSAGE_LISTENER; " +
                        "FIDO WebAuthn bridge will not be enabled",
                )
                return false
            }

            webView.settings.javaScriptEnabled = true

            val bridge = FidoMessageBridge(coroutineScope, fidoClient)

            val fidoJs = FidoJs.CODE.replace(
                FidoJs.BRIDGE_PLACEHOLDER,
                FidoMessageBridge.JS_BRIDGE_NAME,
            )

            // Use "*" to accept messages from any origin at the transport level.
            // Per-message HTTPS and origin validation is enforced in FidoMessageBridge.onPostMessage().
            WebViewCompat.addWebMessageListener(
                webView,
                FidoMessageBridge.JS_BRIDGE_NAME,
                setOf("*"),
                bridge,
            )

            val fidoWebViewClient =
                object : FidoWebViewClient(webViewClient) {
                    override fun onPageStarted(
                        view: WebView?,
                        url: String?,
                        favicon: Bitmap?,
                    ) {
                        super.onPageStarted(view, url, favicon)
                        logger.trace("onPageStarted: {}", url)
                        logger.trace("userAgent: {}", view?.settings?.userAgentString)
                        webView.evaluateJavascript(fidoJs, null)
                    }
                }

            webView.webViewClient = fidoWebViewClient

            webView.webChromeClient =
                object : WebChromeClient() {
                    override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                        consoleMessage?.let {
                            val sourceId = it.sourceId()
                            val isInjectedJs = sourceId.isNullOrEmpty()

                            if (isInjectedJs) {
                                val msg = "$JS_SOURCE_TAG ${it.message()}"
                                @Suppress("LoggingSimilarMessage")
                                when (it.messageLevel()) {
                                    ConsoleMessage.MessageLevel.ERROR -> logger.error(msg)
                                    ConsoleMessage.MessageLevel.WARNING -> logger.warn(msg)
                                    // In WebView: console.debug() → TIP, console.log() → LOG.
                                    // For injected JS we use console.debug() for debug-level
                                    // and console.log() for trace/verbose-level messages.
                                    ConsoleMessage.MessageLevel.DEBUG -> logger.debug(msg)
                                    ConsoleMessage.MessageLevel.TIP -> logger.debug(msg)
                                    // includes ConsoleMessage.MessageLevel.LOG
                                    else -> logger.trace(msg)
                                }
                            } else {
                                logger.trace("$sourceId:${it.lineNumber()} ${it.message()}")
                            }
                        }
                        return true
                    }
                }

            return true
        }
    }
}

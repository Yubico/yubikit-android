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
import com.yubico.yubikit.fido.android.ui.FidoClient
import kotlinx.coroutines.CoroutineScope
import org.slf4j.Logger
import org.slf4j.LoggerFactory

internal class FidoWebViewSupportImpl {
    companion object {
        private val logger: Logger = LoggerFactory.getLogger(FidoWebViewSupportImpl::class.java)
        private const val JS_SOURCE_TAG = "fido.js"

        @JvmStatic
        @SuppressLint("SetJavaScriptEnabled")
        fun enable(
            webView: WebView,
            coroutineScope: CoroutineScope,
            fidoClient: FidoClient,
            webViewClient: WebViewClient,
        ) {
            webView.settings.javaScriptEnabled = true

            val bridge = FidoJsBridge(webView, coroutineScope, fidoClient)

            val fidoJs = FidoJs.CODE.replace(
                FidoJs.BRIDGE_PLACEHOLDER,
                bridge.bridgeName,
            )

            webView.addJavascriptInterface(bridge, bridge.bridgeName)

            val webViewClient =
                object : FidoWebViewClient(webViewClient) {
                    override fun onPageStarted(
                        view: WebView?,
                        url: String?,
                        favicon: Bitmap?,
                    ) {
                        super.onPageStarted(view, url, favicon)
                        logger.trace("onPageStarted: {}", url)
                        logger.trace("userAgent: {}", view?.settings?.userAgentString)
                        bridge.currentOrigin = url?.let { bridge.originFromUrl(it) }
                        webView.evaluateJavascript(fidoJs, null)
                    }
                }

            webView.webViewClient = webViewClient

            webView.webChromeClient =
                object : WebChromeClient() {
                    override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                        consoleMessage?.let {
                            val sourceId = it.sourceId()
                            val isInjectedJs = sourceId.isNullOrEmpty()
                            val msg =
                                if (isInjectedJs) {
                                    "$JS_SOURCE_TAG ${it.message()}"
                                } else {
                                    "$sourceId:${it.lineNumber()} ${it.message()}"
                                }
                            when (it.messageLevel()) {
                                ConsoleMessage.MessageLevel.ERROR -> logger.error(msg)
                                ConsoleMessage.MessageLevel.WARNING -> logger.warn(msg)
                                ConsoleMessage.MessageLevel.DEBUG -> logger.debug(msg)
                                // In WebView: console.debug() → TIP, console.log() → LOG.
                                // For injected JS we use console.debug() for debug-level
                                // and console.log() for trace/verbose-level messages.
                                ConsoleMessage.MessageLevel.TIP ->
                                    if (isInjectedJs) logger.debug(msg) else logger.debug(msg)

                                ConsoleMessage.MessageLevel.LOG ->
                                    if (isInjectedJs) logger.trace(msg) else logger.info(msg)

                                else -> logger.info(msg)
                            }
                        }
                        return true
                    }
                }
        }
    }
}

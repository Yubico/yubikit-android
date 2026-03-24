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

package com.yubico.yubikit.fido.android.ui

import android.webkit.WebView
import android.webkit.WebViewClient
import com.yubico.yubikit.fido.android.ui.internal.FidoWebViewSupportImpl
import kotlinx.coroutines.CoroutineScope

/**
 * Enables FIDO WebAuthn support for this WebView, allowing web pages to perform
 * WebAuthn credential creation and assertion operations using a FIDO security key.
 *
 * This function configures the WebView to intercept `navigator.credentials.create()` and
 * `navigator.credentials.get()` JavaScript calls, routing them through the provided [FidoClient]
 * for hardware-backed authentication.
 *
 * **Configuration performed:**
 * - Enables JavaScript execution on the WebView
 * - Registers a [androidx.webkit.WebViewCompat.WebMessageListener] to handle WebAuthn requests
 *   with per-message origin verification and frame isolation
 * - Sets a custom [android.webkit.WebViewClient] to inject the polyfill on each page load
 *
 * **Security:**
 * - Only HTTPS origins are permitted; requests from non-HTTPS pages are rejected
 * - Requests from subframes (iframes) are rejected by the WebView message listener
 * - Origin attribution uses the per-message `sourceOrigin` provided by the WebView,
 *   not the top-level page URL
 * - Only one WebAuthn request can be in progress at a time
 * - If the WebView implementation does not support
 *   [androidx.webkit.WebViewFeature.WEB_MESSAGE_LISTENER], the bridge is **not** enabled
 *   and this method returns `false` (fail-closed)
 *
 * **HTTP Authentication:**
 * The WebView will display a dialog for HTTP Basic authentication challenges.
 *
 * @param coroutineScope The [CoroutineScope] used to launch coroutines for handling
 *   WebAuthn operations and HTTP authentication dialogs. Should be tied to the
 *   lifecycle of the hosting Activity or Fragment.
 * @param fidoClient The [FidoClient] instance used to perform credential creation
 *   ([FidoClient.makeCredential]) and assertion ([FidoClient.getAssertion]) operations.
 * @param webViewClient An optional custom [WebViewClient] to be chained with the internal
 *   WebViewClient that handles FIDO polyfill injection. If provided, both clients will be
 *   invoked for WebView lifecycle callbacks. Defaults to a new [WebViewClient] instance.
 *
 * @return `true` if the FIDO WebAuthn bridge was successfully enabled, `false` if the
 *   required WebView feature ([androidx.webkit.WebViewFeature.WEB_MESSAGE_LISTENER]) is
 *   not supported by the device's WebView implementation.
 *
 * @see FidoClient
 */
public fun WebView.enableFidoWebauthn(
    coroutineScope: CoroutineScope,
    fidoClient: FidoClient,
    webViewClient: WebViewClient = WebViewClient(),
): Boolean = FidoWebViewSupportImpl.enable(this, coroutineScope, fidoClient, webViewClient)

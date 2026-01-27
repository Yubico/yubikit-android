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

package com.yubico.yubikit.fido.android

import android.webkit.WebView
import com.yubico.yubikit.fido.android.internal.FidoWebViewSupportImpl
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
 * - Injects a JavaScript polyfill that overrides `navigator.credentials` methods
 * - Registers a web message listener to handle WebAuthn requests from the page
 * - Sets a custom [android.webkit.WebViewClient] to inject the polyfill on each page load
 *
 * **Security requirements:**
 * - Only HTTPS origins are permitted; requests from non-HTTPS pages will fail
 * - Requests from subframes (iframes) are not supported
 * - Only one WebAuthn request can be in progress at a time
 *
 * **HTTP Authentication:**
 * The WebView will display a dialog for HTTP Basic authentication challenges.
 *
 * @param coroutineScope The [CoroutineScope] used to launch coroutines for handling
 *   WebAuthn operations and HTTP authentication dialogs. Should be tied to the
 *   lifecycle of the hosting Activity or Fragment.
 * @param fidoClient The [FidoClient] instance used to perform credential creation
 *   ([FidoClient.makeCredential]) and assertion ([FidoClient.getAssertion]) operations.
 *
 * @see FidoClient
 */
public fun WebView.enableFidoWebauthn(
    coroutineScope: CoroutineScope,
    fidoClient: FidoClient,
): Unit = FidoWebViewSupportImpl.enable(this, coroutineScope, fidoClient)

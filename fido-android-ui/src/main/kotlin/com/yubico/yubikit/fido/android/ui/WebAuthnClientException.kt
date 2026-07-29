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

package com.yubico.yubikit.fido.android.ui

/**
 * A terminal WebAuthn client error returned by [FidoClient] when a request cannot be satisfied and
 * retrying would not help — e.g. an unsupported extension request (`largeBlob` write with more than
 * one allowed credential). Distinct from a [kotlin.coroutines.cancellation.CancellationException],
 * which signals the user dismissing the flow: this carries the actual reason so the caller can react
 * to it (a WebView bridge, for instance, rejects the page's promise with a `DOMException` of
 * [webAuthnError]).
 *
 * @property webAuthnError the WebAuthn `DOMException` name for this failure, e.g. `"NotSupportedError"`
 *   (spec `NotSupportedError`) or `"SyntaxError"` (malformed request input).
 */
public class WebAuthnClientException(
    public val webAuthnError: String,
    message: String?,
) : Exception(message)

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

package com.yubico.yubikit.fido.android.ui.internal.ui

internal sealed class Error {
    /**
     * A terminal error: a deterministic, request-level rejection where retrying can never succeed.
     * The UI offers a single dismiss (not "Retry"), and the caller receives the real error — a
     * [com.yubico.yubikit.fido.android.ui.WebAuthnClientException] carrying [webAuthnError] — rather
     * than a cancellation. Every terminal [Error] implements this so the UI button ([isTerminal]),
     * the activity result code, and the returned exception all key off one type; add a new terminal
     * error by implementing this interface and nothing else needs to change.
     *
     * @property webAuthnError the WebAuthn `DOMException` name (e.g. `"NotSupportedError"`).
     * @property message the client's human-readable detail, for logging.
     */
    interface Terminal {
        val webAuthnError: String
        val message: String?
    }

    data object PinRequiredError : Error()

    data object PinComplexityError : Error()

    data object PinNotSetError : Error()

    data object PinBlockedError : Error()

    data object PinAuthBlockedError : Error()

    data object UvBlockedError : Error()

    data object DeviceNotConfiguredError : Error()

    data object DeviceIneligibleError : Error()

    /**
     * The relying party requested an extension configuration that cannot be satisfied (a WebAuthn
     * `NotSupportedError`/`SyntaxError` raised during client extension processing), e.g. a
     * `largeBlob` write with more than one allowed credential. Distinct from
     * [DeviceNotConfiguredError]: nothing is wrong with the key, the request itself is unsupported.
     * The capability-missing subset (credProtect/largeBlob required-but-unsupported) maps to
     * [DeviceIneligibleError] instead.
     *
     * This is a **terminal** error (see [isTerminal]): retrying can never succeed, so the UI offers
     * a single dismiss and the caller receives a [com.yubico.yubikit.fido.android.ui.WebAuthnClientException]
     * carrying [webAuthnError] rather than a cancellation.
     *
     * @property webAuthnError the WebAuthn `DOMException` name (`"NotSupportedError"` or `"SyntaxError"`).
     * @property message the client's human-readable detail, for logging.
     */
    data class ExtensionUnsupportedError(
        override val webAuthnError: String,
        override val message: String?,
    ) : Error(),
        Terminal

    /**
     * Whether retrying this error could plausibly succeed. Terminal errors (a deterministic,
     * request-level rejection) offer a single dismiss instead of "Retry", and are returned to the
     * caller as their real error rather than a cancellation.
     */
    fun isTerminal(): Boolean = this is Terminal

    data class IncorrectPinError(val remainingAttempts: Int?) : Error()

    data class ForcePinChangeError(
        val remainingAttempts: Int?,
    ) : Error()

    data class IncorrectUvError(
        val remainingAttempts: Int,
    ) : Error()

    data class OperationError(
        val exception: Throwable?,
    ) : Error()

    data object TagLostError : Error()

    data object UnknownError : Error()
}

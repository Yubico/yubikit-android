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

import androidx.core.net.toUri

/**
 * Represents the origin of a FIDO authentication request.
 *
 * @property callingApp The origin provided by the calling application.
 * @property resolved The resolved origin. Can be different from callingApp
 */
public data class Origin(
    val callingApp: String,
    val resolved: String = callingApp,
) {
    /**
     * Extracts the host component of [resolved] for use as the effective domain in RP ID
     * validation (see Ctap2Client / Ctap1Client).
     *
     * Uses proper URI parsing instead of string manipulation so that ports
     * (e.g. `https://example.com:8443`) and paths (e.g. `https://example.com/path`) are
     * stripped correctly, yielding a host-only value suitable for the RP ID comparison
     * `effectiveDomain == rpId || effectiveDomain.endsWith("." + rpId)`.
     *
     * Only HTTPS origins are accepted. All current call sites already guarantee that
     * [resolved] is an HTTPS URL; the checks below serve as defensive assertions against
     * future regressions. Non-hierarchical origins such as `android:apk-key-hash:…` must
     * never reach this property — they should supply the RP ID through a separate field.
     *
     * Error messages intentionally omit the actual origin value to avoid leaking
     * potentially sensitive URLs into crash reporters or logs.
     */
    val effectiveDomain: String
        get() {
            val uri = resolved.toUri()
            require(uri.scheme == "https") { "Origin must use HTTPS" }
            return requireNotNull(uri.host) { "Origin must include a valid host" }
        }
}

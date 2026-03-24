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

import androidx.activity.ComponentActivity
import androidx.annotation.MainThread
import androidx.fragment.app.Fragment
import com.yubico.yubikit.fido.android.ui.internal.FidoClientImpl
import com.yubico.yubikit.fido.client.extensions.Extension

/**
 * A client for performing FIDO2/WebAuthn operations using a hardware security key.
 *
 * This interface provides the primary API for creating and asserting WebAuthn credentials
 * using a YubiKey or other FIDO2-compatible authenticator. It handles the full lifecycle
 * of FIDO operations including user interaction, PIN entry, and NFC/USB device communication.
 *
 * **Usage:**
 *
 * Create an instance from a [Fragment] or [ComponentActivity]:
 * ```kotlin
 * val fidoClient = FidoClient(this)
 * ```
 *
 * Then use [makeCredential] for registration or [getAssertion] for authentication:
 * ```kotlin
 * val result = fidoClient.makeCredential(origin, requestJson, null)
 * result.onSuccess { credentialJson -> /* handle success */ }
 * result.onFailure { error -> /* handle error */ }
 * ```
 *
 * **Threading:**
 *
 * All operations are suspending functions and **must be called from the main thread**
 * (e.g., using `Dispatchers.Main`, `lifecycleScope`, or `viewLifecycleOwner.lifecycleScope`).
 * Only one FIDO request can be in progress at a time; attempting to start a new request
 * while one is pending will throw an [IllegalStateException].
 *
 * **Extensions:**
 *
 * Optional FIDO extensions (e.g., largeBlob, PRF) can be provided at construction time
 * or configured globally via [FidoConfigManager.setExtensions].
 *
 * **Lifecycle:**
 *
 * The client uses Android's Activity Result API internally. It must be created during
 * the initialization phase of the [Fragment] or [ComponentActivity] (before `onStart()`).
 *
 * @see FidoConfigManager
 * @see Origin
 */
public interface FidoClient {

    /**
     * Creates a new WebAuthn credential (registration).
     *
     * This corresponds to the `navigator.credentials.create()` WebAuthn API call.
     * Launches a FIDO activity that presents UI for the user to interact with their
     * security key, handle PIN entry if required, and complete the registration ceremony.
     *
     * @param origin The [Origin] of the request, identifying the relying party.
     * @param request JSON string containing the `PublicKeyCredentialCreationOptions`
     *   as defined by the WebAuthn specification.
     * @param clientDataHash Optional pre-computed SHA-256 hash of the client data (hex-encoded).
     *   If `null`, the client data hash is computed internally from the request parameters.
     * @return A [Result] containing the JSON-encoded `PublicKeyCredential` on success,
     *   or an exception on failure. Possible failure causes include:
     *   - [kotlinx.coroutines.CancellationException] if the user cancelled the operation
     *     or the security key was removed
     *   - [IllegalStateException] if a FIDO request is already in progress
     */
    @MainThread
    public suspend fun makeCredential(
        origin: Origin,
        request: String,
        clientDataHash: String?,
    ): Result<String>

    /**
     * Asserts an existing WebAuthn credential (authentication).
     *
     * This corresponds to the `navigator.credentials.get()` WebAuthn API call.
     * Launches a FIDO activity that presents UI for the user to interact with their
     * security key, handle PIN entry if required, and complete the authentication ceremony.
     *
     * @param origin The [Origin] of the request, identifying the relying party.
     * @param request JSON string containing the `PublicKeyCredentialRequestOptions`
     *   as defined by the WebAuthn specification.
     * @param clientDataHash Optional pre-computed SHA-256 hash of the client data (hex-encoded).
     *   If `null`, the client data hash is computed internally from the request parameters.
     * @return A [Result] containing the JSON-encoded `PublicKeyCredential` on success,
     *   or an exception on failure. Possible failure causes include:
     *   - [kotlinx.coroutines.CancellationException] if the user cancelled the operation
     *     or the security key was removed
     *   - [IllegalStateException] if a FIDO request is already in progress
     */
    @MainThread
    public suspend fun getAssertion(
        origin: Origin,
        request: String,
        clientDataHash: String?,
    ): Result<String>

    public companion object {
        /**
         * Creates a [FidoClient] bound to a [Fragment]'s lifecycle.
         *
         * The client registers an activity result launcher with the fragment to handle
         * FIDO UI interactions. Must be called during fragment initialization (before `onStart()`).
         *
         * @param fragment The fragment that will host FIDO UI interactions.
         * @param extensions Optional list of FIDO extensions to enable for all operations.
         *   If provided, these extensions are registered globally via [FidoConfigManager].
         */
        @JvmStatic
        @JvmOverloads
        public operator fun invoke(
            fragment: Fragment,
            extensions: List<Extension>? = null,
        ): FidoClient = FidoClientImpl(fragment, extensions)

        /**
         * Creates a [FidoClient] bound to a [ComponentActivity]'s lifecycle.
         *
         * The client registers an activity result launcher with the activity to handle
         * FIDO UI interactions. Must be called during activity initialization (before `onStart()`).
         *
         * @param activity The activity that will host FIDO UI interactions.
         * @param extensions Optional list of FIDO extensions to enable for all operations.
         *   If provided, these extensions are registered globally via [FidoConfigManager].
         */
        @JvmStatic
        @JvmOverloads
        public operator fun invoke(
            activity: ComponentActivity,
            extensions: List<Extension>? = null,
        ): FidoClient = FidoClientImpl(activity, extensions)
    }
}

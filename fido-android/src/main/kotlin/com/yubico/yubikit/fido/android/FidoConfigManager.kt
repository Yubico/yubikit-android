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

package com.yubico.yubikit.fido.android

import androidx.compose.runtime.Composable
import com.yubico.yubikit.fido.android.internal.config.FidoConfigManagerImpl
import com.yubico.yubikit.fido.client.extensions.Extension
import kotlinx.coroutines.flow.StateFlow

/**
 * Configuration options for the FIDO UI experience.
 *
 * This data class holds all configurable settings that affect how the FIDO operations
 * are presented to the user. Use [FidoConfigManager] to modify the global configuration.
 *
 * @property isPinPrioritized When `true`, the PIN entry UI is shown before prompting for
 *   security key interaction. When `false` (default), the user is prompted to touch
 *   their security key first. Set to `true` for workflows where PIN entry upfront
 *   provides a better user experience.
 * @property fidoExtensions List of FIDO extensions to enable for all operations, or `null`
 *   to use the default set of extensions provided by the underlying CTAP2 client.
 *   The default extensions include: CredBlob, CredProps, CredProtect, HmacSecret,
 *   LargeBlob, and MinPinLength. Provide an explicit list to override or disable
 *   specific extensions.
 * @property customTheme Optional Compose theme wrapper to apply to the FIDO UI screens.
 *   If `null`, the default theme is used. Provide a composable function that wraps
 *   the content with your app's theme for visual consistency.
 *
 * @see FidoConfigManager
 */
public data class FidoConfig(
    val isPinPrioritized: Boolean = false,
    val isCustomThemeEnabled: Boolean = false,
    val fidoExtensions: List<Extension>? = null,
    val customTheme: (@Composable (content: @Composable () -> Unit) -> Unit)? = null,
)

/**
 * Global manager for FIDO UI configuration.
 *
 * This singleton provides methods to read and modify the configuration that controls
 * FIDO operation behavior and UI presentation. Configuration changes are applied
 * globally and affect all [FidoClient] instances.
 *
 * **Reading configuration:**
 * ```kotlin
 * // Get current snapshot
 * val config = FidoConfigManager.current
 *
 * // Observe changes reactively
 * FidoConfigManager.configuration.collect { config ->
 *     // React to configuration changes
 * }
 * ```
 *
 * **Modifying configuration:**
 * ```kotlin
 * // Set individual properties
 * FidoConfigManager.setPrioritizePin(true)
 * FidoConfigManager.setExtensions(listOf(LargeBlobExtension()))
 * FidoConfigManager.setTheme { content -> MyAppTheme { content() } }
 *
 * // Or update atomically
 * FidoConfigManager.update { config ->
 *     config.copy(prioritizePin = true, extensions = listOf(...))
 * }
 *
 * // Or replace entirely
 * FidoConfigManager.replace(FidoConfig(prioritizePin = true))
 * ```
 *
 * **Thread safety:**
 *
 * All operations are thread-safe. The [configuration] flow emits updates atomically.
 *
 * @see FidoConfig
 * @see FidoClient
 */
public object FidoConfigManager {
    /**
     * A [StateFlow] of the current [FidoConfig].
     *
     * Collect this flow to observe configuration changes reactively.
     * The flow emits the current value immediately upon collection.
     */
    public val configuration: StateFlow<FidoConfig>
        get() = FidoConfigManagerImpl.configuration

    /**
     * The current configuration snapshot.
     *
     * This is a convenience property equivalent to `configuration.value`.
     */
    public val current: FidoConfig
        get() = FidoConfigManagerImpl.current

    /**
     * Sets whether PIN entry should be prioritized before security key interaction.
     *
     * @param value `true` to show PIN entry first, `false` to prompt for key touch first.
     */
    public fun setPrioritizePin(value: Boolean): Unit =
        FidoConfigManagerImpl.setPrioritizePin(value)

    /**
     * Sets the FIDO extensions to enable for all operations.
     *
     * @param extensions List of [Extension] instances to enable, or `null` to use
     *   the default set of extensions provided by the CTAP2 client.
     */
    public fun setExtensions(extensions: List<Extension>?): Unit =
        FidoConfigManagerImpl.setExtensions(extensions)

    /**
     * Sets a custom Compose theme for the FIDO UI screens.
     *
     * @param theme A composable function that wraps content with your theme,
     *   or `null` to use the default theme.
     */
    public fun setTheme(theme: (@Composable (content: @Composable () -> Unit) -> Unit)?): Unit =
        FidoConfigManagerImpl.setTheme(theme)

    /**
     * Sets whether to use a custom theme for the FIDO UI screens.
     *
     * @param value `true` to use custom theme, `false` to use default theme.
     */
    public fun setUseCustomTheme(value: Boolean): Unit =
        FidoConfigManagerImpl.setUseCustomTheme(value)

    /**
     * Atomically updates the configuration using a transform function.
     *
     * This is useful when you need to modify multiple properties based on the
     * current configuration state.
     *
     * @param transform A function that receives the current config and returns the new config.
     */
    public fun update(transform: (FidoConfig) -> FidoConfig): Unit =
        FidoConfigManagerImpl.update(transform)

    /**
     * Replaces the entire configuration with a new value.
     *
     * @param configuration The new [FidoConfig] to set.
     */
    public fun replace(configuration: FidoConfig): Unit =
        FidoConfigManagerImpl.replace(configuration)
}

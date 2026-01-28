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

package com.yubico.yubikit.fido.android.providerservice

import androidx.compose.runtime.Composable

/**
 * A singleton provider for registering and retrieving a custom Compose theme
 * to be used by the YubiKit Provider Service UI components.
 *
 * This allows applications to customize the appearance of the provider service
 * dialogs and screens by supplying their own Compose theme wrapper.
 *
 * Example usage:
 * ```
 * YubiKitProviderServiceThemeProvider.register { content ->
 *     MyAppTheme {
 *         content()
 *     }
 * }
 * ```
 */
public object YubiKitProviderServiceThemeProvider {

    @Volatile
    private var theme: (@Composable (@Composable () -> Unit) -> Unit)? = null

    /**
     * Registers a custom Compose theme to be used by the YubiKit Provider Service.
     *
     * The registered theme will wrap the content of provider service UI components,
     * allowing consistent styling with the host application.
     *
     * @param theme A composable function that takes content as a parameter and wraps it
     *              with the desired theme. The function receives a `@Composable` content
     *              block that should be invoked within the theme wrapper.
     */
    public fun register(theme: @Composable (@Composable () -> Unit) -> Unit) {
        YubiKitProviderServiceThemeProvider.theme = theme
    }

    /**
     * Retrieves the currently registered theme, if any.
     *
     * @return The registered theme composable function, or `null` if no theme has been registered.
     */
    public fun get(): (@Composable (@Composable () -> Unit) -> Unit)? = theme
}

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

package com.yubico.yubikit.fido.android.internal.config

import androidx.compose.runtime.Composable
import com.yubico.yubikit.fido.android.FidoConfig
import com.yubico.yubikit.fido.client.extensions.Extension
import kotlinx.coroutines.flow.StateFlow

/**
 * Internal implementation of the FIDO configuration manager.
 *
 * Provides methods to read and mutate the global FIDO UI configuration.
 * All state is stored in [FidoConfigStore].
 */
internal object FidoConfigManagerImpl {
    val configuration: StateFlow<FidoConfig> = FidoConfigStore.config

    val current: FidoConfig
        get() = configuration.value

    fun setPrioritizePin(value: Boolean) {
        update { it.copy(isPinPrioritized = value) }
    }

    fun setExtensions(extensions: List<Extension>?) {
        update { it.copy(fidoExtensions = extensions) }
    }

    fun setTheme(theme: (@Composable (content: @Composable () -> Unit) -> Unit)?) {
        update { it.copy(customTheme = theme) }
    }

    fun setUseCustomTheme(value: Boolean) {
        update { it.copy(isCustomThemeEnabled = value) }
    }

    fun update(transform: (FidoConfig) -> FidoConfig) {
        FidoConfigStore.update(transform)
    }

    fun replace(configuration: FidoConfig) {
        FidoConfigStore.replace(configuration)
    }
}

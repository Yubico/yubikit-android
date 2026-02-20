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

package com.yubico.yubikit.fido.android.ui.internal.config

import com.yubico.yubikit.fido.android.ui.FidoConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/**
 * Shared configuration state for the FIDO Android experience.
 */
internal object FidoConfigStore {
    private val _config = MutableStateFlow(FidoConfig())
    val config: StateFlow<FidoConfig> = _config

    /**
     * Applies a configuration update atomically.
     */
    fun update(transform: (FidoConfig) -> FidoConfig) {
        _config.update(transform)
    }

    /**
     * Replaces the configuration with the provided value.
     */
    fun replace(configuration: FidoConfig) {
        _config.value = configuration
    }
}

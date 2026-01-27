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

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import com.yubico.yubikit.fido.android.config.YubiKitFidoConfig

internal object ProviderServicePreferences {
    private const val PREFS_NAME = "fido_provider_service_prefs"
    private const val KEY_PRIORITIZE_PIN = "prioritize_pin"

    private fun getPrefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun loadConfiguration(context: Context): YubiKitFidoConfig {
        val prefs = getPrefs(context)
        return YubiKitFidoConfig(
            prioritizePin = prefs.getBoolean(KEY_PRIORITIZE_PIN, false),
        )
    }

    fun saveConfiguration(context: Context, config: YubiKitFidoConfig) {
        val prefs = getPrefs(context)
        prefs.edit {
            putBoolean(KEY_PRIORITIZE_PIN, config.prioritizePin)
        }
    }

    fun savePrioritizePin(context: Context, value: Boolean) {
        val prefs = getPrefs(context)
        prefs.edit { putBoolean(KEY_PRIORITIZE_PIN, value) }
    }
}

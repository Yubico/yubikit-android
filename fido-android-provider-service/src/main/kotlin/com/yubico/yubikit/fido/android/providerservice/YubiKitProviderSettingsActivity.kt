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

package com.yubico.yubikit.fido.android.providerservice

import android.content.res.Configuration
import android.os.Bundle
import android.view.WindowInsetsController
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import com.yubico.yubikit.fido.android.FidoConfigManager
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

internal class YubiKitProviderSettingsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Load config from preferences and update ClientConfiguration
        val config = ProviderServicePreferences.loadConfiguration(this)
        FidoConfigManager.replace(config)
        setContent {
            YubiKitProviderServiceTheme {
                SettingsScreen()
            }
        }

        val isDarkMode =
            (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        if (isDarkMode) {
            // Use default (light icons on dark background)
            window.insetsController?.setSystemBarsAppearance(
                0,
                WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS,
            )
        } else {
            // Set dark icons for light background
            window.insetsController?.setSystemBarsAppearance(
                WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS,
                WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS,
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsScreen() {
    var isPinPrioritized by remember { mutableStateOf(false) }
    var isCustomThemeEnabled by remember { mutableStateOf(false) }
    val context = LocalContext.current

    // Get version name
    val versionName = try {
        val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
        packageInfo.versionName ?: ""
    } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
        ""
    }

    LaunchedEffect(Unit) {
        (context as? androidx.lifecycle.LifecycleOwner)?.lifecycleScope?.launch {
            FidoConfigManager.configuration.collectLatest {
                isPinPrioritized = it.isPinPrioritized
                isCustomThemeEnabled = it.isCustomThemeEnabled
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = stringResource(
                                id = R.string.settings_activity_name,
                                stringResource(id = R.string.provider_service_label),
                            ),
                        )
                        Text(
                            text = stringResource(id = R.string.provider_service_settingsSubtitle),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                },
            )
        },
        content = { padding: PaddingValues ->
            Column(
                modifier = Modifier
                    .padding(padding)
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState()),
            ) {
                SettingSwitch(
                    title = stringResource(R.string.assume_pin_exists),
                    checked = isPinPrioritized,
                    onCheckedChange = {
                        FidoConfigManager.setPrioritizePin(it)
                        ProviderServicePreferences.savePrioritizePin(context, it)
                    },
                )
                if (YubiKitProviderServiceThemeProvider.get() != null) {
                    SettingSwitch(
                        title = stringResource(R.string.use_custom_theme),
                        checked = isCustomThemeEnabled,
                        onCheckedChange = {
                            FidoConfigManager.setUseCustomTheme(it)
                            ProviderServicePreferences.saveUseCustomTheme(context, it)
                        },
                    )
                }
                // Spacer to push version to bottom
                Spacer(modifier = Modifier.weight(1f))
                Text(
                    text = stringResource(R.string.version, versionName),
                    modifier = Modifier
                        .align(Alignment.CenterHorizontally)
                        .padding(bottom = 16.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
    )
}

@Composable
private fun SettingSwitch(title: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

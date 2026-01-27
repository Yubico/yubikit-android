package com.yubico.yubikit.fido.android.providerservice

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.outlined.Palette
import androidx.compose.material.icons.outlined.Pin
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.toggleableState
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.lifecycleScope
import com.yubico.yubikit.fido.android.FidoConfigManager
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

internal class YubiKitProviderSettingsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        ProviderServicePreferences.loadConfiguration(this).also {
            FidoConfigManager.replace(it)
        }

        setContent {
            YubiKitProviderServiceTheme {
                SettingsScreen(
                    onNavigateBack = { onBackPressedDispatcher.onBackPressed() },
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun SettingsScreen(onNavigateBack: () -> Unit) {
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

    val hasCustomTheme = YubiKitProviderServiceThemeProvider.get() != null
    val bottomCorner = if (hasCustomTheme) 4.dp else 28.dp

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
                    Text(
                        text = stringResource(R.string.yk_provider_service_settings_activity_name),
                        style = MaterialTheme.typography.titleLarge,
                    )
                },
                navigationIcon = {
                    IconButton(
                        onClick = onNavigateBack,
                        colors = IconButtonDefaults.iconButtonColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                        ),
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.yk_provider_service_navigate_back),
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer,
                ),
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.surfaceContainer)
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
        ) {
            ListItem(
                modifier = Modifier
                    .padding(top = 8.dp)
                    .clip(RoundedCornerShape(28.dp)),
                colors = ListItemDefaults.colors(
                    containerColor = MaterialTheme.colorScheme.surfaceBright,
                ),
                headlineContent = {
                    Text(
                        text = stringResource(R.string.yk_provider_service_settings_label),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                },
                supportingContent = {
                    Text(
                        text = stringResource(
                            R.string.yk_provider_service_version_label,
                            versionName,
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                },
                leadingContent = {
                    val drawable = remember {
                        context.packageManager.getApplicationIcon(context.packageName)
                    }
                    Image(
                        bitmap = drawable.toBitmap(48, 48).asImageBitmap(),
                        contentDescription = null,
                        modifier = Modifier.size(24.dp),
                    )
                },
            )

            Column(
                modifier = Modifier
                    .padding(top = 16.dp)
                    .clip(
                        RoundedCornerShape(
                            bottomStart = bottomCorner,
                            bottomEnd = bottomCorner,
                            topStart = 28.dp,
                            topEnd = 28.dp,
                        ),
                    ),
            ) {
                ExpressiveSettingSwitch(
                    title = stringResource(R.string.yk_provider_service_pref_prioritize_pin),
                    icon = { Icon(Icons.Outlined.Pin, contentDescription = null) },
                    checked = isPinPrioritized,
                    onCheckedChange = {
                        FidoConfigManager.setIsPinPrioritized(it)
                        ProviderServicePreferences.saveIsPinPrioritized(context, it)
                    },
                )
            }

            if (hasCustomTheme) {
                Column(
                    modifier = Modifier
                        .padding(top = 2.dp)
                        .clip(
                            RoundedCornerShape(
                                topStart = 4.dp,
                                topEnd = 4.dp,
                                bottomStart = 28.dp,
                                bottomEnd = 28.dp,
                            ),
                        ),
                ) {
                    ExpressiveSettingSwitch(
                        title = stringResource(R.string.yk_provider_service_pref_use_custom_theme),
                        icon = { Icon(Icons.Outlined.Palette, contentDescription = null) },
                        checked = isCustomThemeEnabled,
                        onCheckedChange = {
                            FidoConfigManager.setIsCustomThemeEnabled(it)
                            ProviderServicePreferences.saveIsCustomThemeEnabled(context, it)
                        },
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun ExpressiveSettingSwitch(
    title: String,
    icon: @Composable () -> Unit,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    ListItem(
        colors = ListItemDefaults.colors(
            containerColor = MaterialTheme.colorScheme.surfaceBright,
        ),
        headlineContent = {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyLarge,
            )
        },
        leadingContent = icon,
        trailingContent = {
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                thumbContent = {
                    Icon(
                        imageVector = if (checked) Icons.Filled.Check else Icons.Filled.Close,
                        contentDescription = null,
                        modifier = Modifier.size(SwitchDefaults.IconSize),
                    )
                },
                modifier = Modifier.semantics {
                    role = Role.Switch
                    toggleableState = if (checked) ToggleableState.On else ToggleableState.Off
                },
            )
        },
    )
}

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

package com.yubico.yubikit.fido.android.ui.internal.ui.components

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.BasicAlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SheetState
import androidx.compose.material3.Surface
import androidx.compose.material3.adaptive.currentWindowAdaptiveInfo
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.movableContentOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.window.core.layout.WindowSizeClass

internal enum class FidoPresentation { BottomSheet, Dialog, FullScreen }

internal val LocalFidoPresentation: ProvidableCompositionLocal<FidoPresentation> =
    compositionLocalOf { FidoPresentation.BottomSheet }

@Composable
internal fun rememberFidoPresentation(): FidoPresentation {
    val sizeClass = currentWindowAdaptiveInfo().windowSizeClass
    return when {
        !sizeClass.isHeightAtLeastBreakpoint(WindowSizeClass.HEIGHT_DP_MEDIUM_LOWER_BOUND) ->
            FidoPresentation.FullScreen
        sizeClass.isWidthAtLeastBreakpoint(WindowSizeClass.WIDTH_DP_MEDIUM_LOWER_BOUND) ->
            FidoPresentation.Dialog
        else ->
            FidoPresentation.BottomSheet
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun FidoUiHost(
    sheetState: SheetState,
    onDismissRequest: () -> Unit,
    content: @Composable () -> Unit,
) {
    val presentation = rememberFidoPresentation()
    val currentContent by rememberUpdatedState(content)
    val movableContent = remember { movableContentOf { currentContent() } }

    CompositionLocalProvider(LocalFidoPresentation provides presentation) {
        when (presentation) {
            FidoPresentation.BottomSheet -> {
                ModalBottomSheet(
                    contentWindowInsets = { WindowInsets(0) },
                    dragHandle = {},
                    sheetState = sheetState,
                    sheetMaxWidth = 480.dp,
                    scrimColor = Color.Transparent,
                    onDismissRequest = onDismissRequest,
                ) {
                    Box(modifier = Modifier.navigationBarsPadding().imePadding()) {
                        movableContent()
                    }
                }
            }

            FidoPresentation.Dialog -> {
                BasicAlertDialog(
                    onDismissRequest = onDismissRequest,
                    properties = DialogProperties(
                        usePlatformDefaultWidth = false,
                        decorFitsSystemWindows = false,
                    ),
                ) {
                    Surface(
                        modifier = Modifier
                            .widthIn(max = 480.dp)
                            .heightIn(max = 560.dp)
                            .imePadding(),
                        shape = MaterialTheme.shapes.extraLarge,
                        color = MaterialTheme.colorScheme.surfaceContainerLow,
                    ) {
                        movableContent()
                    }
                }
            }

            FidoPresentation.FullScreen -> {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.surfaceContainerLow,
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .safeDrawingPadding()
                            .imePadding(),
                    ) {
                        movableContent()
                    }
                }
            }
        }
    }
}

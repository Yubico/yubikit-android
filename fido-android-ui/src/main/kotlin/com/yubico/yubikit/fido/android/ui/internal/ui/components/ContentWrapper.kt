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

package com.yubico.yubikit.fido.android.ui.internal.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.ui.R
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ContentWrapper(
    modifier: Modifier = Modifier,
    operation: FidoClientService.Operation,
    title: String? = null,
    titleTestTag: String? = null,
    onCloseButtonClick: (() -> Unit)? = null,
    hasOwnDismiss: Boolean = false,
    contentHeight: Dp = 160.dp,
    content: @Composable (() -> Unit),
) {
    val presentation = LocalFidoPresentation.current
    val effectiveCloseAction: (() -> Unit)? =
        onCloseButtonClick?.takeUnless { presentation == FidoPresentation.Dialog && hasOwnDismiss }

    if (presentation == FidoPresentation.FullScreen) {
        Column(
            modifier = modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.surfaceContainerLow),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            TopAppBar(
                title = {
                    if (title != null) {
                        Text(
                            text = title,
                            style = MaterialTheme.typography.titleLarge,
                            maxLines = 1,
                            modifier = if (titleTestTag != null) {
                                Modifier.testTag(titleTestTag)
                            } else {
                                Modifier
                            },
                        )
                    }
                },
                navigationIcon = {
                    if (effectiveCloseAction != null) {
                        IconButton(onClick = effectiveCloseAction) {
                            Icon(
                                imageVector = Icons.Default.Close,
                                contentDescription = stringResource(
                                    R.string.yk_fido_content_description_close,
                                ),
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                ),
            )
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Top,
            ) {
                content()
            }
        }
        return
    }

    if (presentation == FidoPresentation.Dialog) {
        Column(
            modifier = modifier
                .padding(top = 8.dp, start = 8.dp, end = 8.dp, bottom = 8.dp)
                .fillMaxWidth()
                .wrapContentHeight()
                .background(MaterialTheme.colorScheme.surfaceContainerLow),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Top,
        ) {
            if (title != null || effectiveCloseAction != null) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (title != null) {
                        Text(
                            text = title,
                            style = MaterialTheme.typography.titleLarge,
                            maxLines = 1,
                            modifier = Modifier
                                .weight(1f)
                                .padding(start = 16.dp)
                                .let { if (titleTestTag != null) it.testTag(titleTestTag) else it },
                        )
                    } else {
                        Spacer(modifier = Modifier.weight(1f))
                    }
                    if (effectiveCloseAction != null) {
                        FilledIconButton(
                            onClick = effectiveCloseAction,
                            modifier = Modifier.padding(4.dp).width(40.dp).height(40.dp),
                            colors = IconButtonDefaults.filledIconButtonColors(
                                containerColor = MaterialTheme.colorScheme.secondaryContainer,
                                contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                            ),
                        ) {
                            Icon(
                                imageVector = Icons.Default.Close,
                                contentDescription = stringResource(
                                    R.string.yk_fido_content_description_close,
                                ),
                            )
                        }
                    }
                }
            }
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .defaultMinSize(minHeight = contentHeight)
                    .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                content()
            }
        }
        return
    }

    Column(
        modifier =
        modifier
            .padding(top = 8.dp, start = 8.dp, end = 8.dp)
            .fillMaxWidth()
            .wrapContentHeight()
            .background(MaterialTheme.colorScheme.surfaceContainerLow),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.End,
            modifier = Modifier.fillMaxWidth().padding(0.dp),
        ) {
            if (effectiveCloseAction != null) {
                FilledIconButton(
                    onClick = effectiveCloseAction,
                    modifier = Modifier.padding(4.dp).width(40.dp).height(40.dp),
                    colors = IconButtonDefaults.filledIconButtonColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer,
                        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                    ),

                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = stringResource(R.string.yk_fido_content_description_close),
                    )
                }
            } else {
                Box(
                    modifier =
                    Modifier
                        .width(16.dp)
                        .height(48.dp),
                )
            }
        }
        Column(
            modifier =
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .defaultMinSize(minHeight = contentHeight)
                .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            if (title != null) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.headlineSmall,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .fillMaxWidth()
                        .let { if (titleTestTag != null) it.testTag(titleTestTag) else it },
                )
            }
            content()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true, showSystemUi = true, device = Devices.PIXEL_4)
@Composable
private fun ContentWrapperInBottomSheetPreview() {
    MaterialTheme {
        ModalBottomSheet(
            contentWindowInsets = { WindowInsets(0) },
            dragHandle = {},
            sheetState = rememberModalBottomSheetState(),
            onDismissRequest = {},
        ) {
            ContentWrapper(
                operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                onCloseButtonClick = {},
            ) {
                PreviewContent()
            }
        }
    }
}

@Composable
private fun PreviewContent(height: Dp = 160.dp) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(height)
            .background(MaterialTheme.colorScheme.surfaceContainerLow),
        contentAlignment = Alignment.Center,
    ) {
        Text("Content")
    }
}

@Preview(showBackground = true)
@Composable
private fun ContentWrapperWithCloseButtonPreview() {
    ContentWrapper(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        onCloseButtonClick = {},
    ) {
        PreviewContent()
    }
}

@Preview(showBackground = true)
@Composable
private fun ContentWrapperWithoutCloseButtonPreview() {
    ContentWrapper(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        onCloseButtonClick = null,
    ) {
        PreviewContent()
    }
}

@Preview(showBackground = true)
@Composable
private fun ContentWrapperHeight320Preview() {
    ContentWrapper(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        contentHeight = 320.dp,
        onCloseButtonClick = {},
    ) {
        PreviewContent(height = 320.dp)
    }
}

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
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.ui.R
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService

@Composable
internal fun ContentWrapper(
    modifier: Modifier = Modifier,
    operation: FidoClientService.Operation,
    origin: String,
    onCloseButtonClick: (() -> Unit)? = null,
    contentHeight: Dp = 160.dp,
    content: @Composable (() -> Unit),
) {
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
            if (onCloseButtonClick != null) {
                FilledIconButton(
                    onClick = onCloseButtonClick,
                    modifier = Modifier.padding(4.dp).width(40.dp).height(40.dp),
                    colors = IconButtonDefaults.filledIconButtonColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
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
                .defaultMinSize(minHeight = contentHeight)
                .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
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
                origin = "example.com",
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
        origin = "example.com",
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
        origin = "example.com",
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
        origin = "example.com",
        contentHeight = 320.dp,
        onCloseButtonClick = {},
    ) {
        PreviewContent(height = 320.dp)
    }
}

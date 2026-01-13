/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.fido.android.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.FidoClientService
import com.yubico.yubikit.fido.android.R

@Composable
fun ContentWrapper(
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
                .fillMaxWidth()
                .padding(top = 0.dp, start = 0.dp, end = 0.dp)
                .wrapContentHeight(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (onCloseButtonClick != null) {
                IconButton(onClick = onCloseButtonClick) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Close",
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
            Text(
                text =
                    if (operation == FidoClientService.Operation.MAKE_CREDENTIAL) {
                        stringResource(R.string.create_passkey_for, origin)
                    } else {
                        stringResource(R.string.login_with_passkey, origin)
                    },
                style = MaterialTheme.typography.titleSmall,
            )
        }
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .defaultMinSize(minHeight = contentHeight),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            content()
        }
    }
}

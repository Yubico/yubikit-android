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

package com.yubico.yubikit.fido.android.ui.internal.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import com.yubico.yubikit.fido.android.ui.R
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService
import com.yubico.yubikit.fido.android.ui.internal.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.ui.internal.ui.components.OperationTitle
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.DefaultPreview
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.FidoAndroidTheme
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity

private val cornerRadius = 12.dp
private val itemSpacing = 2.dp

@Composable
internal fun MultipleAssertionsScreen(
    operation: FidoClientService.Operation,
    origin: String,
    users: List<PublicKeyCredentialUserEntity>,
    onSelect: (Int) -> Unit,
    onCloseButtonClick: () -> Unit,
) {
    val listHeight: Dp = if (users.size > 3) 255.dp else (users.size * 56 + (users.size - 1) * 2).dp
    val scrollable = users.size > 3

    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
        contentHeight = listHeight + 100.dp,
    ) {
        OperationTitle(operation = operation, origin = origin)

        Text(
            text = stringResource(R.string.yk_fido_select_passkey, users.size),
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
        )

        Spacer(modifier = Modifier.height(16.dp))

        Box(
            modifier = Modifier
                .height(listHeight)
                .fillMaxWidth(),
        ) {
            val scrollState = rememberScrollState()
            val canScrollUp = scrollState.value > 0
            val canScrollDown = scrollState.value < scrollState.maxValue

            Column(
                modifier = Modifier
                    .let { if (scrollable) it.verticalScroll(scrollState) else it }
                    .fillMaxWidth(),
            ) {
                users.forEachIndexed { idx, user ->
                    val isFirst = idx == 0
                    val isLast = idx == users.lastIndex
                    val shape = RoundedCornerShape(
                        topStart = if (isFirst) cornerRadius else 0.dp,
                        topEnd = if (isFirst) cornerRadius else 0.dp,
                        bottomStart = if (isLast) cornerRadius else 0.dp,
                        bottomEnd = if (isLast) cornerRadius else 0.dp,
                    )

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(shape)
                            .background(MaterialTheme.colorScheme.surfaceContainerHighest)
                            .clickable { onSelect(idx) }
                            .padding(horizontal = 16.dp, vertical = 16.dp)
                            .testTag("user_button_${user.name}"),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Start,
                    ) {
                        Icon(
                            painter = painterResource(R.drawable.passkey_24px),
                            contentDescription = null,
                            modifier = Modifier.size(24.dp),
                            tint = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = user.displayName,
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    if (!isLast) {
                        Spacer(modifier = Modifier.height(itemSpacing))
                    }
                }
            }

            if (scrollable && canScrollUp) {
                FadeOverlay(
                    alignment = Alignment.TopCenter,
                    colors = listOf(
                        MaterialTheme.colorScheme.surfaceContainerLow,
                        Color.Transparent,
                    ),
                )
            }
            if (scrollable && canScrollDown) {
                FadeOverlay(
                    alignment = Alignment.BottomCenter,
                    colors = listOf(
                        Color.Transparent,
                        MaterialTheme.colorScheme.surfaceContainerLow,
                    ),
                )
            }
        }
    }
}

@Composable
private fun BoxScope.FadeOverlay(
    alignment: Alignment,
    colors: List<Color>,
    height: Dp = 18.dp,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(height)
            .align(alignment)
            .zIndex(1f)
            .background(brush = Brush.verticalGradient(colors = colors)),
    )
}

@DefaultPreview
@Composable
internal fun MultipleAssertionsScreenTwoUsersPreview() {
    FidoAndroidTheme {
        MultipleAssertionsScreen(
            operation = FidoClientService.Operation.GET_ASSERTION,
            origin = "example.com",
            users = listOf(
                PublicKeyCredentialUserEntity("User 1", byteArrayOf(0), "Very long display name"),
                PublicKeyCredentialUserEntity("User 2", byteArrayOf(0), "User 2"),
            ),
            onSelect = {},
            onCloseButtonClick = {},
        )
    }
}

@DefaultPreview
@Composable
internal fun MultipleAssertionsScreenManyUsersPreview() {
    FidoAndroidTheme {
        MultipleAssertionsScreen(
            operation = FidoClientService.Operation.GET_ASSERTION,
            origin = "example.com",
            users = listOf(
                PublicKeyCredentialUserEntity("User 1", byteArrayOf(0), "Longest ever user display name which does not fit"),
                PublicKeyCredentialUserEntity("User 2", byteArrayOf(0), "User 2"),
                PublicKeyCredentialUserEntity("User 3", byteArrayOf(0), "User 3"),
                PublicKeyCredentialUserEntity("User 4", byteArrayOf(0), "User 4"),
                PublicKeyCredentialUserEntity("User 5", byteArrayOf(0), "User 5"),
                PublicKeyCredentialUserEntity("User 6", byteArrayOf(0), "User 6"),
                PublicKeyCredentialUserEntity("User 7", byteArrayOf(0), "User 7"),
                PublicKeyCredentialUserEntity("User 8", byteArrayOf(0), "User 8"),
            ),
            onSelect = {},
            onCloseButtonClick = {},
        )
    }
}

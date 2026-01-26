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

package com.yubico.yubikit.fido.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import com.yubico.yubikit.fido.android.FidoClientService
import com.yubico.yubikit.fido.android.R
import com.yubico.yubikit.fido.android.ui.components.ContentWrapper
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity

@Composable
fun MultipleAssertionsScreen(
    operation: FidoClientService.Operation,
    origin: String,
    users: List<PublicKeyCredentialUserEntity>,
    onSelect: (Int) -> Unit,
    onCloseButtonClick: () -> Unit,
) {
    val height: Dp = if (users.size > 2) 255.dp else 225.dp
    val scrollable = users.size > 3

    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
        contentHeight = height,
    ) {
        Text(
            text = stringResource(R.string.select_passkey, users.size),
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Box(
            modifier =
            Modifier
                .height(height)
                .fillMaxWidth(),
        ) {
            val scrollState = rememberScrollState()
            val canScrollUp = scrollState.value > 0
            val canScrollDown = scrollState.value < scrollState.maxValue

            Column(
                modifier =
                Modifier
                    .let { if (scrollable) it.verticalScroll(scrollState) else it }
                    .fillMaxWidth(),
            ) {
                users.forEachIndexed { idx, user ->
                    Button(
                        onClick = { onSelect(idx) },
                        modifier =
                        Modifier
                            .fillMaxWidth()
                            .height(48.dp)
                            .testTag("user_button_${user.name}"),
                    ) {
                        Icon(
                            painter = painterResource(R.drawable.ic_baseline_passkey_24),
                            contentDescription = null,
                            modifier = Modifier.size(24.dp),
                            tint = MaterialTheme.colorScheme.onPrimary,
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = user.displayName,
                            style = MaterialTheme.typography.bodyLarge,
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                }
            }
            if (scrollable && canScrollUp) {
                FadeOverlay(
                    alignment = Alignment.TopCenter,
                    colors =
                    listOf(
                        MaterialTheme.colorScheme.background,
                        Color.Transparent,
                    ),
                )
            }
            if (scrollable && canScrollDown) {
                FadeOverlay(
                    alignment = Alignment.BottomCenter,
                    colors =
                    listOf(
                        Color.Transparent,
                        MaterialTheme.colorScheme.background,
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
        modifier =
        Modifier
            .fillMaxWidth()
            .height(height)
            .align(alignment)
            .zIndex(1f)
            .background(
                brush = Brush.verticalGradient(colors = colors),
            ),
    )
}

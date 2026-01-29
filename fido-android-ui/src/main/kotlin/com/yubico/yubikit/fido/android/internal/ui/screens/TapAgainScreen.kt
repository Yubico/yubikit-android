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

package com.yubico.yubikit.fido.android.internal.ui.screens

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.R
import com.yubico.yubikit.fido.android.internal.FidoClientService
import com.yubico.yubikit.fido.android.internal.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.internal.ui.theme.DefaultPreview

@Composable
internal fun TapAgainSecurityKey(
    operation: FidoClientService.Operation,
    origin: String,
    onCloseButtonClick: () -> Unit,
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        PulsingIcon(
            painter = painterResource(R.drawable.ic_baseline_passkey_24),
            contentDescription = stringResource(R.string.yk_fido_passkey_icon),
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(text = stringResource(R.string.yk_fido_tap_key_again))
    }
}

@Composable
internal fun PulsingIcon(
    painter: Painter,
    contentDescription: String?,
    modifier: Modifier = Modifier,
    tint: Color = LocalContentColor.current,
) {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")

    val scale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.1f,
        animationSpec =
        infiniteRepeatable(
            animation =
            tween(
                durationMillis = 1000,
                easing = FastOutSlowInEasing,
            ),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "scale",
    )

    val alpha by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 0.7f,
        animationSpec =
        infiniteRepeatable(
            animation =
            tween(
                durationMillis = 1000,
                easing = FastOutSlowInEasing,
            ),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "alpha",
    )

    Icon(
        painter = painter,
        contentDescription = contentDescription,
        modifier =
        modifier
            .scale(scale)
            .alpha(alpha),
        tint = tint,
    )
}

@DefaultPreview
@Composable
internal fun TapSecurityKeyAgainForGetAssertionPreview() {
    TapAgainSecurityKey(
        operation = FidoClientService.Operation.GET_ASSERTION,
        origin = "www.example.com",
    ) {}
}

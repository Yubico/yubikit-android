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

package com.yubico.yubikit.fido.android

import android.content.Context
import android.nfc.NfcAntennaInfo
import android.nfc.NfcManager
import android.os.Build
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.absoluteOffset
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material.icons.rounded.Circle
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

@Composable
fun NfcAntennaHint(
    modifier: Modifier = Modifier,
    iconSize: Dp = 64.dp,
    iconColor: Color = MaterialTheme.colorScheme.primary,
    showAntennas: Boolean = true
) {
    val context = LocalContext.current
    val density = LocalDensity.current
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val scale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.2f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "scale"
    )
    val alpha by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 0.9f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "alpha"
    )
    BoxWithConstraints(
        modifier = modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.35f))
    ) {
        if (!showAntennas) {
            return@BoxWithConstraints
        }
        val boxWidthPx = with(density) { maxWidth.toPx() }
        val boxHeightPx = with(density) { maxHeight.toPx() }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val nfcManager = context.getSystemService(Context.NFC_SERVICE) as? NfcManager
            val nfcAdapter = nfcManager?.defaultAdapter
            val nfcAntennaInfo: NfcAntennaInfo? = nfcAdapter?.nfcAntennaInfo
            if (nfcAntennaInfo != null) {
                val deviceWidthMm = nfcAntennaInfo.deviceWidth
                val deviceHeightMm = nfcAntennaInfo.deviceHeight
                val antennas = nfcAntennaInfo.availableNfcAntennas
                val mmToPxX = boxWidthPx / deviceWidthMm
                val mmToPxY = boxHeightPx / deviceHeightMm
                antennas.forEach { antenna ->
                    val xPx = antenna.locationX * mmToPxX
                    val yPx = antenna.locationY * mmToPxY

                    Box(
                        modifier = Modifier
                            .absoluteOffset(
                                x = with(density) { xPx.toDp() - iconSize / 2 },
                                y = with(density) { yPx.toDp() - iconSize / 2 }
                            )
                            .size(iconSize)
                    ) {

                        Icon(
                            imageVector = Icons.Rounded.Circle,
                            modifier = Modifier
                                .align(Alignment.Center)
                                .size(iconSize)
                                .graphicsLayer(
                                    scaleX = scale,
                                    scaleY = scale,
                                    alpha = 0.5f
                                ),
                            contentDescription = stringResource(R.string.content_description_nfc_antenna_location),
                            tint = MaterialTheme.colorScheme.primaryContainer
                        )
                        Icon(
                            imageVector = Icons.Outlined.Nfc,
                            modifier = Modifier
                                .align(Alignment.Center)
                                .size(iconSize / 2.0f + 1.dp)
                                .graphicsLayer(
                                    scaleX = scale,
                                    scaleY = scale,
                                    alpha = 1.0f
                                ),
                            contentDescription = stringResource(R.string.content_description_nfc_antenna_location),
                            tint = Color.White
                        )
                        Icon(
                            imageVector = Icons.Outlined.Nfc,
                            modifier = Modifier
                                .align(Alignment.Center)
                                .size(iconSize / 2.0f)
                                .graphicsLayer(
                                    scaleX = scale,
                                    scaleY = scale,
                                    alpha = alpha
                                ),
                            contentDescription = stringResource(R.string.content_description_nfc_antenna_location),
                            tint = iconColor
                        )
                    }
                }
            }
        }
    }
}

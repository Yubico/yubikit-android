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

import android.app.Activity
import android.content.Context
import android.nfc.NfcAdapter
import android.nfc.NfcAntennaInfo
import android.nfc.NfcManager
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.TagTechnology
import android.os.Build
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.rounded.StarOutline
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.delay
import java.io.IOException


@Composable
fun NfcUsageGuide(
    onDisposed: () -> Unit = { },
    onClose: () -> Unit,
) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {

        var tagConnected by remember { mutableStateOf(false) }

        val nfcManager = LocalContext.current.getSystemService(Context.NFC_SERVICE) as? NfcManager
        val nfcAdapter = nfcManager?.defaultAdapter ?: return

        if (!nfcAdapter.isEnabled) {
            return
        }

        val nfcAntennaInfo: NfcAntennaInfo? = nfcAdapter.nfcAntennaInfo

        if (nfcAntennaInfo != null) {
            val deviceWidthInMm = nfcAntennaInfo.deviceWidth
            val deviceHeightInMm = nfcAntennaInfo.deviceHeight
            val availableAntennas = nfcAntennaInfo.availableNfcAntennas
            val statusBarPaddingValues = WindowInsets.statusBars.asPaddingValues()
            val topOffset = statusBarPaddingValues.calculateTopPadding()

            BoxWithConstraints(
                modifier = Modifier
                    .fillMaxSize()
                    .background(color = MaterialTheme.colorScheme.background.copy(alpha = 0.9f))
            ) {
                val containerWidthInDp = maxWidth.value
                val containerHeightInDp = maxHeight.value

                val dpPerMmX = containerWidthInDp / deviceWidthInMm
                val dpPerMmY = containerHeightInDp / deviceHeightInMm

                NfcReader(
                    onTagDiscovered = { _ ->
                        tagConnected = true
                    },
                    onTagLost = {
                        tagConnected = false
                    },
                    onDisposed = onDisposed
                )

                IconButton(modifier = Modifier.padding(start = 8.dp, top = topOffset), onClick = onClose) {
                    Icon(Icons.Filled.Close, contentDescription = "close", tint = MaterialTheme.colorScheme.onBackground)
                }

                Text(
                    text = "This screen shows the NFC antenna locations on your phone.",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onBackground,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .padding(16.dp)
                        .offset(y = 48.dp + topOffset)
                )

                Text(
                    text = "To use NFC with your YubiKey, place it on the back of the phone at the antenna area.",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onBackground,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(top = topOffset, bottom = 72.dp, start = 16.dp, end = 16.dp)
                )

                Text(
                    text = "Try that!",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onBackground,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = 32.dp, start = 16.dp, end = 16.dp)
                )

                availableAntennas.forEachIndexed { index, antenna ->
                    val offsetX = (antenna.locationX * dpPerMmX).dp
                    val offsetY = (antenna.locationY * dpPerMmY).dp
                    val contentSize = 128.dp

                    val centeredOffsetX = offsetX - (contentSize / 2f)
                    val centeredOffsetY = offsetY - (contentSize / 2f)

                    LiveIcon(
                        tagPresent = tagConnected,
                        modifier = Modifier
                            .offset(centeredOffsetX, centeredOffsetY)
                            .size(contentSize),
                    )
                }
            }
        }
    }
}

@Composable
fun NfcReader(
    onTagDiscovered: (Tag) -> Unit,
    onTagLost: () -> Unit,
    onDisposed: () -> Unit
) {
    val context = LocalContext.current
    val activity = context as? Activity

    val activeTagConnection = remember { mutableStateOf<TagTechnology?>(null) }
    val nfcAdapter = remember { NfcAdapter.getDefaultAdapter(context) }

    val readerCallback = remember {
        NfcAdapter.ReaderCallback { tag ->
            val isoDep = IsoDep.get(tag)
            if (isoDep != null) {
                try {
                    activeTagConnection.value?.close()
                    isoDep.connect()
                    activeTagConnection.value = isoDep
                    onTagDiscovered(tag)
                } catch (_: IOException) {
                    activeTagConnection.value = null
                    onTagLost()
                }
            }
        }
    }

    LaunchedEffect(activeTagConnection.value) {
        val connection = activeTagConnection.value ?: return@LaunchedEffect
        try {
            while (connection.isConnected) {
                delay(500)
            }
        } catch (_: SecurityException) {
            activeTagConnection.value = null
            onTagLost()
            return@LaunchedEffect
        }

        activeTagConnection.value = null
        onTagLost()
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (activity == null) return@LifecycleEventObserver

            when (event) {
                Lifecycle.Event.ON_RESUME -> {
                    nfcAdapter?.enableReaderMode(
                        activity,
                        readerCallback,
                        NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                        null
                    )
                }

                Lifecycle.Event.ON_PAUSE -> {
                    nfcAdapter?.disableReaderMode(activity)
                    activeTagConnection.value?.close()
                    activeTagConnection.value = null
                    onTagLost()
                }

                else -> {
                }
            }
        }

        lifecycleOwner.lifecycle.addObserver(observer)

        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            activeTagConnection.value?.close()
            activeTagConnection.value = null
            if (activity != null) {
                nfcAdapter?.disableReaderMode(activity)
            }
            onDisposed()
        }
    }
}

@Composable
fun LiveIcon(
    tagPresent: Boolean,
    modifier: Modifier = Modifier
) {
    var rotationAngle by remember { mutableFloatStateOf(0f) }
    var velocity by remember { mutableFloatStateOf(0f) }
    var hue by remember { mutableFloatStateOf(0f) }

    val iconColor = if (tagPresent) {
        Color.hsv(hue, 1f, 1f)
    } else {
        MaterialTheme.colorScheme.onSurface
    }


    LaunchedEffect(tagPresent) {
        if (tagPresent) {
            while (true) {
                velocity += 1.6f
                hue = (hue + 4f) % 360f
                delay(16)
            }
        }
    }

    LaunchedEffect(Unit) {
        while (true) {
            if (velocity > 0f) {
                rotationAngle += velocity
                velocity *= 0.91f

                if (velocity < 0.1f) {
                    velocity = 0f
                }
            }
            delay(16)
        }
    }

    Icon(
        imageVector = Icons.Rounded.StarOutline,
        contentDescription = "Spinning Icon",
        tint = iconColor,
        modifier = modifier
            .graphicsLayer {
                rotationZ = rotationAngle
            }
    )
}
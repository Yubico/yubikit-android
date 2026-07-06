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

package com.yubico.yubikit.fido.android.ui

import android.content.Context
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.ui.internal.nfcAntennaInfo
import com.yubico.yubikit.fido.android.ui.internal.NfcAntennaHint as InternalNfcAntennaHint

/**
 * Returns true if the device reports NFC antenna positions that can be
 * visualized by [NfcAntennaHint].
 *
 * Returns false on Android versions below API 34, when NFC is unavailable,
 * or when the device does not expose antenna location data.
 *
 * @param context A context used to access the NFC system service.
 */
public fun supportsNfcAntennaHint(context: Context): Boolean = nfcAntennaInfo(context) != null

/**
 * Displays animated NFC antenna location indicators on top of the current
 * layout, positioned at the physical NFC antenna locations reported by the
 * device.
 *
 * Has no visible effect on Android below API 34 or on devices that do not
 * expose antenna location data. Use [supportsNfcAntennaHint] to check
 * support before showing this composable.
 *
 * @param modifier Modifier applied to the full-size container.
 * @param iconSize Size of each antenna indicator icon. Defaults to 64.dp.
 * @param iconColor Color of the NFC icon. Defaults to the primary theme color.
 * @param showAntennas Whether to show the antenna indicators. Defaults to true.
 */
@Composable
public fun NfcAntennaHint(
    modifier: Modifier = Modifier,
    iconSize: Dp = 64.dp,
    iconColor: Color = MaterialTheme.colorScheme.primary,
    showAntennas: Boolean = true,
): Unit = InternalNfcAntennaHint(
    modifier = modifier,
    iconSize = iconSize,
    iconColor = iconColor,
    showAntennas = showAntennas,
)

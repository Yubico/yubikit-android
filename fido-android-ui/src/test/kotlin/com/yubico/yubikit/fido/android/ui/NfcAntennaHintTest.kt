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

package com.yubico.yubikit.fido.android.ui

import android.content.Context
import android.content.pm.PackageManager
import android.nfc.AvailableNfcAntenna
import android.nfc.NfcAdapter
import android.nfc.NfcAntennaInfo
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toPixelMap
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.test.core.app.ApplicationProvider
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.FidoAndroidTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import org.robolectric.shadows.ShadowNfcAdapter

/**
 * UI tests for the public [NfcAntennaHint] composable.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35]) // TODO sdk 36 needs Java 21
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class NfcAntennaHintTest {
    @get:Rule
    val composeTestRule = createComposeRule()

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        shadowOf(context.packageManager).setSystemFeature(PackageManager.FEATURE_NFC, true)
        ShadowNfcAdapter.setNfcHardwareExists(true)
        val adapter = NfcAdapter.getDefaultAdapter(context)
        shadowOf(adapter).setNfcAntennaInfo(
            NfcAntennaInfo(70, 150, false, listOf(AvailableNfcAntenna(35, 75))),
        )
    }

    @Test
    fun `iconBorderColor draws a border around the antenna indicator`() {
        setHint(iconBorderColor = BORDER_COLOR)

        assertTrue(borderPixelCount() > 0)
    }

    @Test
    fun `no border is drawn by default`() {
        setHint(iconBorderColor = null)

        assertEquals(0, borderPixelCount())
    }

    private fun setHint(iconBorderColor: Color?) {
        composeTestRule.setContent {
            FidoAndroidTheme {
                NfcAntennaHint(
                    iconColor = Color.Blue,
                    iconBorderColor = iconBorderColor,
                )
            }
        }
    }

    private fun borderPixelCount(): Int {
        val pixels = composeTestRule.onRoot().captureToImage().toPixelMap()
        var count = 0
        for (x in 0 until pixels.width) {
            for (y in 0 until pixels.height) {
                if (pixels[x, y] == BORDER_COLOR) count++
            }
        }
        return count
    }

    private companion object {
        val BORDER_COLOR = Color.Red
    }
}

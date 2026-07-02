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

package com.yubico.yubikit.fido.android.ui.screens

import android.content.Context
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.core.app.ApplicationProvider
import com.yubico.yubikit.fido.android.ui.R
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService
import com.yubico.yubikit.fido.android.ui.internal.ui.screens.TapOrInsertSecurityKey
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.FidoAndroidTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * UI tests for TapOrInsertSecurityKey screen.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35]) // TODO sdk 36 needs Java 21
class TapOrInsertScreenTest {
    @get:Rule
    val composeTestRule = createComposeRule()

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `nfc unavailable shows usb subtitle`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                TapOrInsertSecurityKey(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    isNfcAvailable = false,
                    onCloseButtonClick = {},
                )
            }
        }

        composeTestRule.onNodeWithText(
            context.getString(R.string.yk_fido_plug_your_key_subtitle),
        ).assertExists()
    }

    @Test
    fun `nfc available shows nfc subtitle`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                TapOrInsertSecurityKey(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    isNfcAvailable = true,
                    onCloseButtonClick = {},
                )
            }
        }

        composeTestRule.onNodeWithText(
            context.getString(R.string.yk_fido_connect_your_key_subtitle),
        ).assertExists()
    }
}

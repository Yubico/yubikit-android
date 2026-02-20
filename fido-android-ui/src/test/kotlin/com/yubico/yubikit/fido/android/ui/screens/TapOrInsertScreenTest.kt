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

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService
import com.yubico.yubikit.fido.android.ui.internal.ui.screens.TapOrInsertSecurityKey
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.FidoAndroidTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * UI tests for TapOrInsertSecurityKey screen.
 */
@RunWith(RobolectricTestRunner::class)
class TapOrInsertScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private val testOrigin = "example.com"

    @Test
    fun `nfc unavailable shows warning message`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                TapOrInsertSecurityKey(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    isNfcAvailable = false,
                    origin = testOrigin,
                    onCloseButtonClick = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("nfc_not_available_text").assertExists()
    }

    @Test
    fun `nfc available hides warning message`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                TapOrInsertSecurityKey(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    isNfcAvailable = true,
                    origin = testOrigin,
                    onCloseButtonClick = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("nfc_not_available_text").assertDoesNotExist()
    }
}

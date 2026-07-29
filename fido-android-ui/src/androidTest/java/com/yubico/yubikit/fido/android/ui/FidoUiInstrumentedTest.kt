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

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService
import com.yubico.yubikit.fido.android.ui.internal.ui.Error
import com.yubico.yubikit.fido.android.ui.internal.ui.screens.EnterPin
import com.yubico.yubikit.fido.android.ui.internal.ui.screens.TapOrInsertSecurityKey
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.FidoAndroidTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests that run on actual devices or emulators.
 * These tests verify UI rendering across different screen configurations.
 *
 * Run with different device configurations using Gradle Managed Devices:
 * ./gradlew smallPhoneDebugAndroidTest
 * ./gradlew largePhoneDebugAndroidTest
 * ./gradlew tabletDebugAndroidTest
 * ./gradlew allDevicesGroupDebugAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class FidoUiInstrumentedTest {
    @get:Rule
    val composeTestRule = createComposeRule()

    private val testRpId = "example.com"

    @Test
    fun pinEntryScreen_displaysAllRequiredElements() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                EnterPin(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    rpId = testRpId,
                    onCloseButtonClick = {},
                    onPinEntered = {},
                )
            }
        }

        // Verify all critical UI elements are visible
        composeTestRule.onNodeWithText("Confirm with PIN")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Confirm", ignoreCase = true)
            .assertIsDisplayed()
        composeTestRule.onNodeWithText(testRpId, substring = true)
            .assertIsDisplayed()
    }

    // ========== Tap or Insert Screen Tests ==========

    @Test
    fun tapOrInsertScreen_displaysAllRequiredElements() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                TapOrInsertSecurityKey(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    isNfcAvailable = true,
                    onCloseButtonClick = {},
                )
            }
        }

        composeTestRule.onNodeWithText("Connect your security key")
            .assertIsDisplayed()
    }

    @Test
    fun tapOrInsertScreen_withNfcUnavailable() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                TapOrInsertSecurityKey(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    isNfcAvailable = false,
                    onCloseButtonClick = {},
                )
            }
        }

        composeTestRule.onNodeWithText("Plug in your USB security key.")
            .assertIsDisplayed()
    }

    @Test
    fun tapOrInsertScreen_withNfcAvailable() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                TapOrInsertSecurityKey(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    isNfcAvailable = true,
                    onCloseButtonClick = {},
                )
            }
        }

        composeTestRule.onNodeWithText("Hold your security key against", substring = true)
            .assertIsDisplayed()
    }

    @Test
    fun pinEntryScreen_withIncorrectPinError_showsErrorMessage() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                EnterPin(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    rpId = testRpId,
                    error = Error.IncorrectPinError(remainingAttempts = 3),
                    onCloseButtonClick = {},
                    onPinEntered = {},
                )
            }
        }

        // Error message with remaining attempts should be visible
        composeTestRule
            .onNodeWithText("3", substring = true)
            .assertIsDisplayed()
    }

    @Test
    fun pinEntryScreen_withPinBlockedError_showsBlockedMessage() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                EnterPin(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    rpId = testRpId,
                    error = Error.PinBlockedError,
                    onCloseButtonClick = {},
                    onPinEntered = {},
                )
            }
        }

        composeTestRule
            .onNodeWithText("blocked", substring = true, ignoreCase = true)
            .assertIsDisplayed()
    }
}

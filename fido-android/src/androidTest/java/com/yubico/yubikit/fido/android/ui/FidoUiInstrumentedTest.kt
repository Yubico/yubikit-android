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
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.yubico.yubikit.fido.android.FidoClientService
import com.yubico.yubikit.fido.android.ui.screens.EnterPin
import com.yubico.yubikit.fido.android.ui.screens.TapOrInsertSecurityKey
import com.yubico.yubikit.fido.android.ui.theme.FidoAndroidTheme
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

    private val testOrigin = "example.com"

    @Test
    fun pinEntryScreen_displaysAllRequiredElements() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                EnterPin(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    onCloseButtonClick = {},
                    onPinEntered = {},
                )
            }
        }

        // Verify all critical UI elements are visible
        composeTestRule.onNodeWithText("PIN", substring = true, ignoreCase = true)
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Continue", ignoreCase = true)
            .assertIsDisplayed()
        composeTestRule.onNodeWithContentDescription("Close")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText(testOrigin, substring = true)
            .assertIsDisplayed()
    }

    @Test
    fun pinEntryScreen_forMakeCredential_showsCorrectTitle() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                EnterPin(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    onCloseButtonClick = {},
                    onPinEntered = {},
                )
            }
        }

        composeTestRule.onNodeWithText("passkey", substring = true, ignoreCase = true)
            .assertIsDisplayed()
    }

    @Test
    fun pinEntryScreen_forGetAssertion_showsCorrectTitle() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                EnterPin(
                    operation = FidoClientService.Operation.GET_ASSERTION,
                    origin = testOrigin,
                    onCloseButtonClick = {},
                    onPinEntered = {},
                )
            }
        }

        composeTestRule.onNodeWithText("Login", substring = true, ignoreCase = true)
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
                    origin = testOrigin,
                    onCloseButtonClick = {},
                )
            }
        }

        composeTestRule.onNodeWithText("Tap or insert", substring = true, ignoreCase = true)
            .assertIsDisplayed()
        composeTestRule.onNodeWithContentDescription("Close")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText(testOrigin, substring = true)
            .assertIsDisplayed()
    }

    @Test
    fun tapOrInsertScreen_withNfcUnavailable_showsWarning() {
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

        composeTestRule.onNodeWithText("NFC not available", ignoreCase = true)
            .assertIsDisplayed()
    }

    @Test
    fun tapOrInsertScreen_withNfcAvailable_hidesWarning() {
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

        composeTestRule.onNodeWithText("NFC not available", ignoreCase = true)
            .assertDoesNotExist()
    }

    @Test
    fun pinEntryScreen_withIncorrectPinError_showsErrorMessage() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                EnterPin(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    error = Error.IncorrectPinError(remainingAttempts = 3),
                    onCloseButtonClick = {},
                    onPinEntered = {},
                )
            }
        }

        // Error message with remaining attempts should be visible
        composeTestRule.onNodeWithText("3", substring = true)
            .assertIsDisplayed()
    }

    @Test
    fun pinEntryScreen_withPinBlockedError_showsBlockedMessage() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                EnterPin(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    error = Error.PinBlockedError,
                    onCloseButtonClick = {},
                    onPinEntered = {},
                )
            }
        }

        composeTestRule.onNodeWithText("blocked", substring = true, ignoreCase = true)
            .assertIsDisplayed()
    }
}

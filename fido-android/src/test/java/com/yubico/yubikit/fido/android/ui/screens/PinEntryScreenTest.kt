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

import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import com.yubico.yubikit.fido.android.FidoClientService
import com.yubico.yubikit.fido.android.ui.Error
import com.yubico.yubikit.fido.android.ui.theme.FidoAndroidTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PinEntryScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private fun setEnterPinContent(
        operation: FidoClientService.Operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin: String = "example.com",
        pin: CharArray? = null,
        error: Error? = null,
        onCloseButtonClick: () -> Unit = {},
        onPinEntered: (CharArray) -> Unit = {},
    ) {
        composeTestRule.setContent {
            FidoAndroidTheme {
                EnterPin(
                    operation = operation,
                    origin = origin,
                    pin = pin,
                    error = error,
                    onCloseButtonClick = onCloseButtonClick,
                    onPinEntered = onPinEntered,
                )
            }
        }
    }

    @Test
    fun `continue button enabled only when PIN has at least 4 characters`() {
        setEnterPinContent()

        composeTestRule.onNodeWithText("Continue", ignoreCase = true)
            .assertIsNotEnabled()

        composeTestRule.onNodeWithText("PIN", substring = true, ignoreCase = true)
            .performTextInput("123")
        composeTestRule.onNodeWithText("Continue", ignoreCase = true)
            .assertIsNotEnabled()

        composeTestRule.onNodeWithText("PIN", substring = true, ignoreCase = true)
            .performTextInput("4")
        composeTestRule.onNodeWithText("Continue", ignoreCase = true)
            .assertIsEnabled()
    }

    @Test
    fun `continue button enabled when PIN is pre-filled`() {
        setEnterPinContent(pin = "123456".toCharArray())

        composeTestRule.onNodeWithText("Continue", ignoreCase = true)
            .assertIsEnabled()
    }

    @Test
    fun `clicking continue invokes callback with entered PIN`() {
        var enteredPin = ""
        setEnterPinContent(onPinEntered = { enteredPin = String(it) })

        composeTestRule.onNodeWithText("PIN", substring = true, ignoreCase = true)
            .performTextInput("123456")
        composeTestRule.onNodeWithText("Continue", ignoreCase = true)
            .performClick()

        assertEquals("123456", enteredPin)
    }

    @Test
    fun `displays remaining attempts for incorrect PIN error`() {
        setEnterPinContent(error = Error.IncorrectPinError(remainingAttempts = 3))

        composeTestRule.onNodeWithText("Incorrect PIN. 3 attempts remaining.")
            .assertExists()
    }

    @Test
    fun `displays singular form for 1 remaining attempt`() {
        setEnterPinContent(error = Error.IncorrectPinError(remainingAttempts = 1))

        composeTestRule.onNodeWithText("Incorrect PIN. 1 attempt remaining.")
            .assertExists()
    }

    @Test
    fun `displays generic message when attempts count is null`() {
        setEnterPinContent(error = Error.IncorrectPinError(remainingAttempts = null))

        composeTestRule.onNodeWithText("Incorrect PIN.")
            .assertExists()
    }

    @Test
    fun `displays blocked message when PIN is blocked`() {
        setEnterPinContent(error = Error.PinBlockedError)

        composeTestRule.onNodeWithText("PIN is blocked. You have to reset the key.")
            .assertExists()
    }

    @Test
    fun `displays reconnect message when PIN auth is blocked`() {
        setEnterPinContent(error = Error.PinAuthBlockedError)

        composeTestRule.onNodeWithText("PIN authentication is blocked. Reconnect the key.")
            .assertExists()
    }
}

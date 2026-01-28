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
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import com.yubico.yubikit.fido.android.internal.FidoClientService
import com.yubico.yubikit.fido.android.internal.ui.Error
import com.yubico.yubikit.fido.android.internal.ui.screens.EnterPin
import com.yubico.yubikit.fido.android.internal.ui.theme.FidoAndroidTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
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

        composeTestRule.onNodeWithTag("continue_button")
            .assertIsNotEnabled()

        composeTestRule.onNodeWithTag("pin_input_field")
            .performTextInput("123")
        composeTestRule.onNodeWithTag("continue_button")
            .assertIsNotEnabled()

        composeTestRule.onNodeWithTag("pin_input_field")
            .performTextInput("4")
        composeTestRule.onNodeWithTag("continue_button")
            .assertIsEnabled()
    }

    @Test
    fun `continue button enabled when PIN is pre-filled`() {
        setEnterPinContent(pin = "123456".toCharArray())

        composeTestRule.onNodeWithTag("continue_button")
            .assertIsEnabled()
    }

    @Test
    fun `clicking continue invokes callback with entered PIN`() {
        var enteredPin = ""
        setEnterPinContent(onPinEntered = { enteredPin = String(it) })

        composeTestRule.onNodeWithTag("pin_input_field")
            .performTextInput("123456")
        composeTestRule.onNodeWithTag("continue_button")
            .performClick()

        assertEquals("123456", enteredPin)
    }

    @Test
    fun `displays remaining attempts for incorrect PIN error`() {
        setEnterPinContent(error = Error.IncorrectPinError(remainingAttempts = 3))

        composeTestRule.onNodeWithTag("pin_error_text")
            .assertExists()
    }

    @Test
    fun `displays singular form for 1 remaining attempt`() {
        setEnterPinContent(error = Error.IncorrectPinError(remainingAttempts = 1))

        composeTestRule.onNodeWithTag("pin_error_text")
            .assertExists()
    }

    @Test
    fun `displays generic message when attempts count is null`() {
        setEnterPinContent(error = Error.IncorrectPinError(remainingAttempts = null))

        composeTestRule.onNodeWithTag("pin_error_text")
            .assertExists()
    }

    @Test
    fun `displays blocked message when PIN is blocked`() {
        setEnterPinContent(error = Error.PinBlockedError)

        composeTestRule.onNodeWithTag("pin_error_text")
            .assertExists()
    }

    @Test
    fun `displays reconnect message when PIN auth is blocked`() {
        setEnterPinContent(error = Error.PinAuthBlockedError)

        composeTestRule.onNodeWithTag("pin_error_text")
            .assertExists()
    }
}

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
import com.yubico.yubikit.fido.android.internal.ui.screens.CreatePinScreen
import com.yubico.yubikit.fido.android.internal.ui.screens.DEFAULT_MIN_PIN_LENGTH
import com.yubico.yubikit.fido.android.internal.ui.screens.ForceChangePinScreen
import com.yubico.yubikit.fido.android.internal.ui.theme.FidoAndroidTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CreatePinScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private fun setCreatePinContent(
        minPinLen: Int = DEFAULT_MIN_PIN_LENGTH,
        error: Error? = null,
        onCreatePin: (CharArray) -> Unit = {},
    ) {
        composeTestRule.setContent {
            FidoAndroidTheme {
                CreatePinScreen(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = "example.com",
                    minPinLen = minPinLen,
                    error = error,
                    onCloseButtonClick = {},
                    onCreatePin = onCreatePin,
                )
            }
        }
    }

    @Test
    fun `create button disabled when PINs do not match`() {
        setCreatePinContent()

        composeTestRule.onNodeWithTag("new_pin_input")
            .performTextInput("1234")
        composeTestRule.onNodeWithTag("repeat_pin_input")
            .performTextInput("5678")

        composeTestRule.onNodeWithTag("create_pin_button")
            .assertIsNotEnabled()
    }

    @Test
    fun `create button disabled when PIN shorter than minimum length`() {
        setCreatePinContent(minPinLen = 6)

        composeTestRule.onNodeWithTag("new_pin_input")
            .performTextInput("1234")
        composeTestRule.onNodeWithTag("repeat_pin_input")
            .performTextInput("1234")

        composeTestRule.onNodeWithTag("create_pin_button")
            .assertIsNotEnabled()
    }

    @Test
    fun `create button enabled when PINs match and meet minimum length`() {
        setCreatePinContent(minPinLen = 4)

        composeTestRule.onNodeWithTag("new_pin_input")
            .performTextInput("123456")
        composeTestRule.onNodeWithTag("repeat_pin_input")
            .performTextInput("123456")

        composeTestRule.onNodeWithTag("create_pin_button")
            .assertIsEnabled()
    }

    @Test
    fun `create button invokes callback with entered PIN`() {
        var createdPin = ""
        setCreatePinContent(onCreatePin = { createdPin = String(it) })

        composeTestRule.onNodeWithTag("new_pin_input")
            .performTextInput("123456")
        composeTestRule.onNodeWithTag("repeat_pin_input")
            .performTextInput("123456")
        composeTestRule.onNodeWithTag("create_pin_button")
            .performClick()

        assertEquals("123456", createdPin)
    }

    @Test
    fun `displays error for PIN complexity failure`() {
        setCreatePinContent(error = Error.PinComplexityError)

        composeTestRule.onNodeWithTag("pin_error_text")
            .assertExists()
    }
}

@RunWith(RobolectricTestRunner::class)
class ForceChangePinScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private fun setForceChangePinContent(
        minPinLen: Int = DEFAULT_MIN_PIN_LENGTH,
        error: Error? = null,
        onChangePin: (currentPin: CharArray, newPin: CharArray) -> Unit = { _, _ -> },
    ) {
        composeTestRule.setContent {
            FidoAndroidTheme {
                ForceChangePinScreen(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = "example.com",
                    minPinLen = minPinLen,
                    error = error,
                    onCloseButtonClick = {},
                    onChangePin = onChangePin,
                )
            }
        }
    }

    @Test
    fun `shows info text explaining why PIN change is required`() {
        setForceChangePinContent()

        composeTestRule.onNodeWithTag("pin_info_text")
            .assertExists()
    }

    @Test
    fun `shows Change PIN button instead of Create PIN`() {
        setForceChangePinContent()

        composeTestRule.onNodeWithTag("change_pin_button")
            .assertExists()
        composeTestRule.onNodeWithTag("create_pin_button")
            .assertDoesNotExist()
    }

    @Test
    fun `displays error for incorrect current PIN`() {
        setForceChangePinContent(error = Error.IncorrectPinError(remainingAttempts = 3))

        composeTestRule.onNodeWithTag("pin_error_text")
            .assertExists()
    }

    @Test
    fun `displays error for PIN complexity failure in change flow`() {
        setForceChangePinContent(error = Error.PinComplexityError)

        composeTestRule.onNodeWithTag("pin_error_text")
            .assertExists()
    }
}

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

        composeTestRule.onNodeWithText("New PIN", substring = true, ignoreCase = true)
            .performTextInput("1234")
        composeTestRule.onNodeWithText("Repeat PIN", substring = true, ignoreCase = true)
            .performTextInput("5678")

        composeTestRule.onNodeWithText("Create PIN", ignoreCase = true)
            .assertIsNotEnabled()
    }

    @Test
    fun `create button disabled when PIN shorter than minimum length`() {
        setCreatePinContent(minPinLen = 6)

        composeTestRule.onNodeWithText("New PIN", substring = true, ignoreCase = true)
            .performTextInput("1234")
        composeTestRule.onNodeWithText("Repeat PIN", substring = true, ignoreCase = true)
            .performTextInput("1234")

        composeTestRule.onNodeWithText("Create PIN", ignoreCase = true)
            .assertIsNotEnabled()
    }

    @Test
    fun `create button enabled when PINs match and meet minimum length`() {
        setCreatePinContent(minPinLen = 4)

        composeTestRule.onNodeWithText("New PIN", substring = true, ignoreCase = true)
            .performTextInput("123456")
        composeTestRule.onNodeWithText("Repeat PIN", substring = true, ignoreCase = true)
            .performTextInput("123456")

        composeTestRule.onNodeWithText("Create PIN", ignoreCase = true)
            .assertIsEnabled()
    }

    @Test
    fun `create button invokes callback with entered PIN`() {
        var createdPin = ""
        setCreatePinContent(onCreatePin = { createdPin = String(it) })

        composeTestRule.onNodeWithText("New PIN", substring = true, ignoreCase = true)
            .performTextInput("123456")
        composeTestRule.onNodeWithText("Repeat PIN", substring = true, ignoreCase = true)
            .performTextInput("123456")
        composeTestRule.onNodeWithText("Create PIN", ignoreCase = true)
            .performClick()

        assertEquals("123456", createdPin)
    }

    @Test
    fun `displays error for PIN complexity failure`() {
        setCreatePinContent(error = Error.PinComplexityError)

        composeTestRule.onNodeWithText("complex", substring = true, ignoreCase = true)
            .assertExists()
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
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

        composeTestRule.onNodeWithText("For security reasons", substring = true, ignoreCase = true)
            .assertExists()
    }

    @Test
    fun `shows Change PIN button instead of Create PIN`() {
        setForceChangePinContent()

        composeTestRule.onNodeWithText("Change PIN", ignoreCase = true)
            .assertExists()
        composeTestRule.onNodeWithText("Create PIN", ignoreCase = true)
            .assertDoesNotExist()
    }

    @Test
    fun `displays error for incorrect current PIN`() {
        setForceChangePinContent(error = Error.IncorrectPinError(remainingAttempts = 3))

        composeTestRule.onNodeWithText("Incorrect PIN. 3 attempts remaining.")
            .assertExists()
    }

    @Test
    fun `displays error for PIN complexity failure in change flow`() {
        setForceChangePinContent(error = Error.PinComplexityError)

        composeTestRule.onNodeWithText("complex", substring = true, ignoreCase = true)
            .assertExists()
    }
}

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
import androidx.compose.ui.test.performClick
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.android.internal.FidoClientService
import com.yubico.yubikit.fido.android.internal.ui.Error
import com.yubico.yubikit.fido.android.internal.ui.screens.ErrorView
import com.yubico.yubikit.fido.android.internal.ui.screens.SuccessView
import com.yubico.yubikit.fido.android.internal.ui.theme.FidoAndroidTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ResultScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private val testOrigin = "example.com"

    @Test
    fun `successView shows passkey created message for MAKE_CREDENTIAL`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                SuccessView(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                )
            }
        }

        composeTestRule.onNodeWithTag("result_message_text").assertExists()
    }

    @Test
    fun `successView shows login successful message for GET_ASSERTION`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                SuccessView(
                    operation = FidoClientService.Operation.GET_ASSERTION,
                    origin = testOrigin,
                )
            }
        }

        composeTestRule.onNodeWithTag("result_message_text").assertExists()
    }

    @Test
    fun `errorView shows no credentials message for ERR_NO_CREDENTIALS`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                ErrorView(
                    operation = FidoClientService.Operation.GET_ASSERTION,
                    origin = testOrigin,
                    error = Error.OperationError(CtapException(CtapException.ERR_NO_CREDENTIALS)),
                    onRetry = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("error_message_text").assertExists()
    }

    @Test
    fun `errorView shows timeout message for ERR_USER_ACTION_TIMEOUT`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                ErrorView(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    error = Error.OperationError(CtapException(CtapException.ERR_USER_ACTION_TIMEOUT)),
                    onRetry = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("error_message_text").assertExists()
    }

    @Test
    fun `errorView shows key store full message for ERR_KEY_STORE_FULL`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                ErrorView(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    error = Error.OperationError(CtapException(CtapException.ERR_KEY_STORE_FULL)),
                    onRetry = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("error_message_text").assertExists()
    }

    @Test
    fun `errorView shows credential excluded message for ERR_CREDENTIAL_EXCLUDED`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                ErrorView(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    error = Error.OperationError(CtapException(CtapException.ERR_CREDENTIAL_EXCLUDED)),
                    onRetry = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("error_message_text").assertExists()
    }

    @Test
    fun `errorView shows unknown error for unhandled CTAP error`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                ErrorView(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    error = Error.OperationError(CtapException(CtapException.ERR_OTHER)),
                    onRetry = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("error_message_text").assertExists()
    }

    @Test
    fun `errorView shows device not configured message for DeviceNotConfiguredError`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                ErrorView(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    error = Error.DeviceNotConfiguredError,
                    onRetry = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("error_message_text").assertExists()
    }

    @Test
    fun `errorView shows custom message for UnknownError with message`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                ErrorView(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    error = Error.UnknownError("Custom error message"),
                    onRetry = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("error_message_text").assertExists()
    }

    @Test
    fun `errorView shows unknown error for UnknownError without message`() {
        composeTestRule.setContent {
            FidoAndroidTheme {
                ErrorView(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    error = Error.UnknownError(null),
                    onRetry = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("error_message_text").assertExists()
    }

    @Test
    fun `errorView retry button invokes callback`() {
        var retryCalled = false
        composeTestRule.setContent {
            FidoAndroidTheme {
                ErrorView(
                    operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                    origin = testOrigin,
                    error = Error.OperationError(RuntimeException()),
                    onRetry = { retryCalled = true },
                )
            }
        }

        composeTestRule.onNodeWithTag("retry_button").performClick()

        assertTrue(retryCalled)
    }
}

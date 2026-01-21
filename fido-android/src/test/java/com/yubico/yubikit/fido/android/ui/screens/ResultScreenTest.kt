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

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.android.FidoClientService
import com.yubico.yubikit.fido.android.ui.Error
import com.yubico.yubikit.fido.android.ui.theme.FidoAndroidTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class ResultScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private val testOrigin = "example.com"

    // ========== SuccessView tests ==========

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

        composeTestRule.onNodeWithText("Passkey successfully created")
            .assertIsDisplayed()
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

        composeTestRule.onNodeWithText("Login with passkey was successful")
            .assertIsDisplayed()
    }

    // ========== ErrorView CTAP exception tests ==========

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

        composeTestRule.onNodeWithText("No passkeys for $testOrigin exist on the security key.")
            .assertIsDisplayed()
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

        composeTestRule.onNodeWithText("The operation timed out. Please try again.")
            .assertIsDisplayed()
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

        composeTestRule.onNodeWithText("There is no space free for passkeys", substring = true)
            .assertIsDisplayed()
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

        composeTestRule.onNodeWithText("Cannot create this passkey", substring = true)
            .assertIsDisplayed()
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

        composeTestRule.onNodeWithText("Unknown error")
            .assertIsDisplayed()
    }

    // ========== ErrorView other error types ==========

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

        composeTestRule.onNodeWithText("The security key cannot be used, make sure PIN is set.")
            .assertIsDisplayed()
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

        composeTestRule.onNodeWithText("Custom error message")
            .assertIsDisplayed()
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

        composeTestRule.onNodeWithText("Unknown error")
            .assertIsDisplayed()
    }

    // ========== Retry button test ==========

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

        composeTestRule.onNodeWithText("Retry")
            .performClick()

        assertTrue(retryCalled)
    }
}

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
import com.yubico.yubikit.fido.android.internal.FidoClientService
import com.yubico.yubikit.fido.android.internal.ui.Error
import com.yubico.yubikit.fido.android.internal.ui.screens.MatchFingerprint
import com.yubico.yubikit.fido.android.internal.ui.theme.FidoAndroidTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class UvInputScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private fun setMatchFingerprintContent(error: Error? = null) {
        composeTestRule.setContent {
            FidoAndroidTheme {
                MatchFingerprint(
                    operation = FidoClientService.Operation.GET_ASSERTION,
                    origin = "example.com",
                    error = error,
                    onCloseButtonClick = {},
                )
            }
        }
    }

    @Test
    fun `displays remaining attempts on UV error`() {
        setMatchFingerprintContent(error = Error.IncorrectUvError(remainingAttempts = 2))

        composeTestRule.onNodeWithTag("uv_error_text").assertExists()
    }

    @Test
    fun `displays fallback to PIN message when no attempts remaining`() {
        setMatchFingerprintContent(error = Error.IncorrectUvError(remainingAttempts = 0))

        composeTestRule.onNodeWithTag("uv_error_text").assertExists()
    }
}

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
import com.yubico.yubikit.fido.android.internal.FidoClientService
import com.yubico.yubikit.fido.android.internal.ui.screens.MultipleAssertionsScreen
import com.yubico.yubikit.fido.android.internal.ui.theme.FidoAndroidTheme
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MultipleAssertionsScreenTest {
    @get:Rule
    val composeTestRule = createComposeRule()

    private fun createUser(displayName: String) = PublicKeyCredentialUserEntity(
        displayName,
        ByteArray(16),
        displayName,
    )

    @Test
    fun `selecting a user invokes callback with correct index`() {
        var selectedIndex = -1
        val users = listOf(
            createUser("Alice"),
            createUser("Bob"),
            createUser("Charlie"),
        )

        composeTestRule.setContent {
            FidoAndroidTheme {
                MultipleAssertionsScreen(
                    operation = FidoClientService.Operation.GET_ASSERTION,
                    origin = "example.com",
                    users = users,
                    onSelect = { selectedIndex = it },
                    onCloseButtonClick = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("user_button_Bob").performClick()
        assertEquals(1, selectedIndex)
    }

    @Test
    fun `displays all user options`() {
        val users = listOf(
            createUser("Alice"),
            createUser("Bob"),
        )

        composeTestRule.setContent {
            FidoAndroidTheme {
                MultipleAssertionsScreen(
                    operation = FidoClientService.Operation.GET_ASSERTION,
                    origin = "example.com",
                    users = users,
                    onSelect = {},
                    onCloseButtonClick = {},
                )
            }
        }

        composeTestRule.onNodeWithTag("user_button_Alice").assertExists()
        composeTestRule.onNodeWithTag("user_button_Bob").assertExists()
    }
}

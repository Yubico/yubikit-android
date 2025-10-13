/*
 * Copyright (C) 2025 Yubico.
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

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import com.yubico.yubikit.fido.android.FidoClientService
import com.yubico.yubikit.fido.android.R
import com.yubico.yubikit.fido.android.ui.Error
import com.yubico.yubikit.fido.android.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.ui.theme.DefaultPreview
import kotlin.compareTo

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun EnterPin(
    operation: FidoClientService.Operation,
    origin: String,
    error: Error? = null,
    onCloseButtonClick: () -> Unit,
    pin: String? = "",
    onPinEntered: (pin: String) -> Unit
) {

    val errorText: String? = when (error) {
        is Error.IncorrectPinError -> {
            if (error.remainingAttempts != null) {
                stringResource(
                    R.string.incorrect_pin_with_attempts,
                    error.remainingAttempts
                )
            } else {
                stringResource(R.string.incorrect_pin)
            }
        }

        is Error.PinBlockedError -> {
            stringResource(R.string.pin_blocked)
        }

        is Error.PinAuthBlockedError -> {
            stringResource(R.string.pin_auth_blocked)
        }

        else -> null
    }

    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        var text by remember {
            mutableStateOf(
                if (!pin.isNullOrEmpty()) {
                    TextFieldValue(pin, selection = TextRange(0, pin.length))
                } else {
                    TextFieldValue("")
                }
            )
        }
        var showPassword by remember { mutableStateOf(false) }
        val focusRequester = remember { FocusRequester() }
        val keyboardController = LocalSoftwareKeyboardController.current
        val isPinValid = text.text.length >= 4

        LaunchedEffect(Unit) {
            focusRequester.requestFocus()
            keyboardController?.show()
        }

        OutlinedTextField(
            modifier = Modifier
                .fillMaxWidth()
                .focusRequester(focusRequester),
            value = text,
            supportingText = { Text(text = errorText ?: "") },
            trailingIcon = {
                IconButton(onClick = { showPassword = !showPassword }) {
                    Icon(
                        imageVector = if (showPassword) {
                            Icons.Default.VisibilityOff
                        } else {
                            Icons.Default.Visibility
                        },
                        contentDescription = "Show"
                    )
                }
            },
            singleLine = true,
            isError = errorText != null,
            label = { Text(text = stringResource(R.string.provide_pin)) },
            leadingIcon = {
                Icon(
                    imageVector = Icons.Default.Password,
                    contentDescription = stringResource(
                        R.string.icon_content_description_password
                    ),
                    tint = MaterialTheme.colorScheme.onBackground
                )
            },
            visualTransformation = if (!showPassword) {
                PasswordVisualTransformation()
            } else {
                VisualTransformation.None
            },
            onValueChange = {
                text = it
            },
            keyboardOptions = KeyboardOptions.Default.copy(imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(
                onDone = {
                    if (isPinValid) {
                        onPinEntered.invoke(text.text)
                    }
                }
            )
        )


        Row(
            modifier = Modifier
                .fillMaxWidth(),
            horizontalArrangement = Arrangement.End
        ) {
            Button(
                modifier = Modifier.width(IntrinsicSize.Min),
                onClick = {
                    if (isPinValid) {
                        onPinEntered.invoke(text.text)
                    }
                },
                enabled = isPinValid,
                shapes = ButtonDefaults.shapes()
            ) {
                Text(text = stringResource(R.string.continue_operation), maxLines = 1)
            }
        }

    }
}

@DefaultPreview
@Composable
fun EnterPinPreview() {
    EnterPin(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        onCloseButtonClick = {}) {}
}

@DefaultPreview
@Composable
fun EnterPinWithErrorPreview() {
    EnterPin(
        operation = FidoClientService.Operation.GET_ASSERTION,
        origin = "example.com",
        error = Error.IncorrectPinError(3),
        onCloseButtonClick = {}) {}
}

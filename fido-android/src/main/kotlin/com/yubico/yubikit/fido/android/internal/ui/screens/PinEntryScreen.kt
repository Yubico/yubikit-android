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

package com.yubico.yubikit.fido.android.internal.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.R
import com.yubico.yubikit.fido.android.internal.FidoClientService
import com.yubico.yubikit.fido.android.internal.ui.Error
import com.yubico.yubikit.fido.android.internal.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.internal.ui.theme.DefaultPreview

@Composable
internal fun resolvePinEntryError(error: Error?): String? =
    when (error) {
        is Error.IncorrectPinError -> {
            if (error.remainingAttempts != null) {
                pluralStringResource(
                    R.plurals.yk_fido_incorrect_pin_with_attempts,
                    count = error.remainingAttempts,
                    error.remainingAttempts,
                )
            } else {
                stringResource(R.string.yk_fido_incorrect_pin)
            }
        }

        is Error.PinBlockedError -> {
            stringResource(R.string.yk_fido_pin_blocked)
        }

        is Error.PinAuthBlockedError -> {
            stringResource(R.string.yk_fido_pin_auth_blocked)
        }

        else -> null
    }

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
internal fun EnterPin(
    operation: FidoClientService.Operation,
    origin: String,
    error: Error? = null,
    onCloseButtonClick: () -> Unit,
    pin: CharArray? = null,
    onPinEntered: (pin: CharArray) -> Unit,
) {
    val errorText = resolvePinEntryError(error)

    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        var text by remember {
            mutableStateOf(
                if (pin != null) {
                    TextFieldValue(
                        String(pin),
                        selection = TextRange(0, pin.size),
                    )
                } else {
                    TextFieldValue("")
                },
            )
        }
        var showPassword by remember { mutableStateOf(false) }
        val focusRequester = remember { FocusRequester() }
        val keyboardController = LocalSoftwareKeyboardController.current
        val isPinValid = text.text.length >= 4

        val submit: () -> Unit = {
            if (isPinValid) {
                onPinEntered.invoke(text.text.toCharArray())
            }
        }

        LaunchedEffect(Unit) {
            focusRequester.requestFocus()
            keyboardController?.show()
        }

        OutlinedTextField(
            modifier =
            Modifier
                .fillMaxWidth()
                .focusRequester(focusRequester)
                .testTag("pin_input_field"),
            value = text,
            trailingIcon = {
                IconButton(onClick = { showPassword = !showPassword }) {
                    Icon(
                        imageVector =
                        if (showPassword) {
                            Icons.Default.VisibilityOff
                        } else {
                            Icons.Default.Visibility
                        },
                        contentDescription = "Show",
                    )
                }
            },
            singleLine = true,
            isError = errorText != null,
            label = { Text(text = stringResource(R.string.yk_fido_provide_pin)) },
            leadingIcon = {
                Icon(
                    imageVector = Icons.Default.Password,
                    contentDescription =
                    stringResource(
                        R.string.yk_fido_icon_content_description_password,
                    ),
                    tint = MaterialTheme.colorScheme.onBackground,
                )
            },
            visualTransformation =
            if (!showPassword) {
                PasswordVisualTransformation()
            } else {
                VisualTransformation.None
            },
            onValueChange = {
                text = it
            },
            keyboardOptions = KeyboardOptions.Default.copy(
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.Password,
                imeAction = ImeAction.Done,
            ),
            keyboardActions =
            KeyboardActions(
                onDone = { submit.invoke() },
            ),
        )
        if (errorText != null) {
            Text(
                text = errorText,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 8.dp, bottom = 4.dp).testTag("pin_error_text"),
            )
        }

        Row(
            modifier =
            Modifier
                .fillMaxWidth(),
            horizontalArrangement = Arrangement.End,
        ) {
            Button(
                onClick = submit,
                enabled = isPinValid,
                shapes = ButtonDefaults.shapes(),
                modifier = Modifier.width(IntrinsicSize.Min).testTag("continue_button"),
            ) {
                Text(text = stringResource(R.string.yk_fido_continue_operation), maxLines = 1)
            }
        }
    }
}

@DefaultPreview
@Composable
internal fun EnterPinPreview() {
    EnterPin(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        onCloseButtonClick = {},
    ) {}
}

@DefaultPreview
@Composable
internal fun EnterPinWithErrorPreview() {
    EnterPin(
        operation = FidoClientService.Operation.GET_ASSERTION,
        origin = "example.com",
        error = Error.IncorrectPinError(3),
        onCloseButtonClick = {},
    ) {}
}

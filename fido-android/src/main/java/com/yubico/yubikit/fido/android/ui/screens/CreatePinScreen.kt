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
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
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
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.FidoClientService
import com.yubico.yubikit.fido.android.R
import com.yubico.yubikit.fido.android.ui.Error
import com.yubico.yubikit.fido.android.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.ui.theme.DefaultPreview

const val DEFAULT_MIN_PIN_LENGTH = 4

@Composable
fun CreatePinScreen(
    operation: FidoClientService.Operation,
    origin: String,
    error: Error? = null,
    minPinLen: Int = DEFAULT_MIN_PIN_LENGTH,
    onCloseButtonClick: () -> Unit,
    onCreatePin: (pin: String) -> Unit
) {
    var newPin by remember { mutableStateOf(TextFieldValue("")) }
    var repeatPin by remember { mutableStateOf(TextFieldValue("")) }
    var showNewPin by remember { mutableStateOf(false) }
    var showRepeatPin by remember { mutableStateOf(false) }
    val newPinFocusRequester = remember { FocusRequester() }
    val repeatPinFocusRequester = remember { FocusRequester() }
    val keyboardController = LocalSoftwareKeyboardController.current

    val errorText: String? = when (error) {
        is Error.PinComplexityError -> stringResource(R.string.pin_is_not_complex_enough)
        null -> null
        else -> stringResource(R.string.creating_pin_failed)
    }

    LaunchedEffect(Unit) {
        newPinFocusRequester.requestFocus()
        keyboardController?.show()
    }

    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
        contentHeight = 320.dp
    ) {
        Text(
            text = stringResource(R.string.info_no_pin_set),
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.padding(vertical = 8.dp)
        )

        PinTextField(
            value = newPin,
            onValueChange = { newPin = it },
            label = stringResource(R.string.new_pin, minPinLen),
            showPin = showNewPin,
            onToggleShowPin = { showNewPin = !showNewPin },
            modifier = Modifier
                .fillMaxWidth()
                .focusRequester(newPinFocusRequester),
            keyboardOptions = KeyboardOptions.Default.copy(imeAction = ImeAction.Next),
            keyboardActions = KeyboardActions(onNext = { repeatPinFocusRequester.requestFocus() })
        )

        PinTextField(
            value = repeatPin,
            onValueChange = { repeatPin = it },
            label = stringResource(R.string.repeat_pin),
            showPin = showRepeatPin,
            onToggleShowPin = { showRepeatPin = !showRepeatPin },
            modifier = Modifier
                .fillMaxWidth()
                .focusRequester(repeatPinFocusRequester),
            keyboardOptions = KeyboardOptions.Default.copy(imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(
                onDone = {
                    if (isPinValid(newPin.text, repeatPin.text, minPinLen)) {
                        onCreatePin(newPin.text)
                    }
                }
            )
        )

        if (errorText != null) {
            Text(
                text = errorText,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
            horizontalArrangement = Arrangement.End
        ) {
            Button(
                onClick = onCloseButtonClick,
                modifier = Modifier.padding(end = 8.dp)
            ) {
                Text(stringResource(R.string.cancel))
            }
            Button(
                onClick = {
                    onCreatePin(newPin.text)
                },
                enabled = isPinValid(newPin.text, repeatPin.text, minPinLen)
            ) {
                Text(stringResource(R.string.create_pin))
            }
        }
    }
}

private fun isPinValid(newPin: String, repeatPin: String, minPinLen: Int?): Boolean {
    return newPin.isNotEmpty() && newPin == repeatPin && newPin.length >= (minPinLen ?: 4)
    // Add more checks if needed (e.g., length, complexity)
}

@Composable
fun PinTextField(
    value: TextFieldValue,
    onValueChange: (TextFieldValue) -> Unit,
    label: String,
    showPin: Boolean,
    onToggleShowPin: () -> Unit,
    modifier: Modifier = Modifier,
    keyboardOptions: KeyboardOptions,
    keyboardActions: KeyboardActions
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        leadingIcon = {
            Icon(
                imageVector = Icons.Default.Password,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onBackground
            )
        },
        trailingIcon = {
            IconButton(onClick = onToggleShowPin) {
                Icon(
                    imageVector = if (showPin) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                    contentDescription = "Show"
                )
            }
        },
        singleLine = true,
        visualTransformation = if (!showPin) PasswordVisualTransformation() else VisualTransformation.None,
        modifier = modifier,
        keyboardOptions = keyboardOptions,
        keyboardActions = keyboardActions
    )
}

@Composable
fun PinCreatedScreen(
    operation: FidoClientService.Operation,
    origin: String,
    onCloseButtonClick: () -> Unit,
    onContinue: () -> Unit
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        contentHeight = 200.dp,
        onCloseButtonClick = onCloseButtonClick
    ) {
        Text(
            text = stringResource(R.string.pin_successfully_created),
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.padding(vertical = 24.dp)
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 16.dp),
            horizontalArrangement = Arrangement.End
        ) {
            Button(
                onClick = onContinue
            ) {
                Text(stringResource(R.string.continue_operation))
            }
        }
    }
}

@DefaultPreview
@Composable
fun CreatePinPreview() {
    CreatePinScreen(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        onCreatePin = {},
        onCloseButtonClick = {})
}

@DefaultPreview
@Composable
fun CreatePinErrorPreview() {
    CreatePinScreen(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        error = Error.PinComplexityError,
        onCreatePin = {},
        onCloseButtonClick = {})
}

@DefaultPreview
@Composable
fun PinCreatedPreview() {
    PinCreatedScreen(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        onContinue = {},
        onCloseButtonClick = {}
    )
}

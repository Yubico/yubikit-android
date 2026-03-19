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

package com.yubico.yubikit.fido.android.ui.internal.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedSecureTextField
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
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.ui.R
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService
import com.yubico.yubikit.fido.android.ui.internal.ui.Error
import com.yubico.yubikit.fido.android.ui.internal.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.DefaultPreview

internal const val DEFAULT_MIN_PIN_LENGTH: Int = 4

@Composable
internal fun CreatePinScreen(
    operation: FidoClientService.Operation,
    origin: String,
    error: Error? = null,
    minPinLen: Int = DEFAULT_MIN_PIN_LENGTH,
    onCloseButtonClick: () -> Unit,
    onCreatePin: (newPin: CharArray) -> Unit,
) {
    CreateChangePinScreen(
        operation = operation,
        origin = origin,
        error = error,
        minPinLen = minPinLen,
        forceChangePin = false,
        onCloseButtonClick = onCloseButtonClick,
    ) { newPin, _ ->
        onCreatePin(newPin)
    }
}

@Composable
internal fun ForceChangePinScreen(
    operation: FidoClientService.Operation,
    origin: String,
    error: Error? = null,
    minPinLen: Int = DEFAULT_MIN_PIN_LENGTH,
    currentPin: CharArray? = null,
    onCloseButtonClick: () -> Unit,
    onChangePin: (currentPin: CharArray, newPin: CharArray) -> Unit,
) {
    CreateChangePinScreen(
        operation = operation,
        origin = origin,
        error = error,
        minPinLen = minPinLen,
        forceChangePin = true,
        currentPin = currentPin,
        onCloseButtonClick = onCloseButtonClick,
    ) { newPin, enteredCurrentPin ->
        onChangePin(enteredCurrentPin, newPin)
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun CreateChangePinScreen(
    operation: FidoClientService.Operation,
    origin: String,
    error: Error? = null,
    minPinLen: Int = DEFAULT_MIN_PIN_LENGTH,
    forceChangePin: Boolean = false,
    currentPin: CharArray? = null,
    onCloseButtonClick: () -> Unit,
    onPinAction: (newPin: CharArray, currentPin: CharArray) -> Unit,
) {
    val currentPinState = rememberTextFieldState(initialText = currentPin?.let { String(it) } ?: "")
    val newPinState = rememberTextFieldState()
    val repeatPinState = rememberTextFieldState()
    var showCurrentPin by remember { mutableStateOf(false) }
    var showNewPin by remember { mutableStateOf(false) }
    var showRepeatPin by remember { mutableStateOf(false) }
    val currentPinFocusRequester = remember { FocusRequester() }
    val newPinFocusRequester = remember { FocusRequester() }
    val repeatPinFocusRequester = remember { FocusRequester() }
    val keyboardController = LocalSoftwareKeyboardController.current

    val currentPinErrorText: String? = resolvePinEntryError(error)

    val newPinErrorText: String? =
        when {
            currentPinErrorText != null -> null
            error is Error.PinComplexityError -> stringResource(R.string.yk_fido_pin_is_not_complex_enough)
            error == null -> null
            else -> stringResource(R.string.yk_fido_creating_pin_failed)
        }

    val submit: () -> Unit = {
        if (isPinValid(newPinState.text.toString(), repeatPinState.text.toString(), minPinLen)) {
            onPinAction(
                newPinState.text.toString().toCharArray(),
                currentPinState.text.toString().toCharArray(),
            )
        }
    }

    LaunchedEffect(Unit) {
        if (forceChangePin && currentPin == null) {
            currentPinFocusRequester.requestFocus()
        } else {
            newPinFocusRequester.requestFocus()
        }
        keyboardController?.show()
    }

    ContentWrapper(
        operation = operation,
        origin = origin,
        onCloseButtonClick = onCloseButtonClick,
        contentHeight = 320.dp,
    ) {
        Text(
            text =
            stringResource(
                if (forceChangePin) {
                    R.string.yk_fido_info_force_change_pin
                } else {
                    R.string.yk_fido_info_no_pin_set
                },
            ),
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier
                .padding(vertical = 8.dp)
                .testTag("pin_info_text"),
        )

        if (forceChangePin) {
            PinTextField(
                state = currentPinState,
                label = stringResource(R.string.yk_fido_current_pin),
                showPin = showCurrentPin,
                onToggleShowPin = { showCurrentPin = !showCurrentPin },
                modifier =
                Modifier
                    .padding(bottom = if (currentPinErrorText == null) 16.dp else 0.dp)
                    .fillMaxWidth()
                    .focusRequester(currentPinFocusRequester)
                    .testTag("current_pin_input"),
                keyboardOptions =
                KeyboardOptions.Default.copy(
                    imeAction = ImeAction.Next,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Password,
                ),
                onKeyboardAction = { newPinFocusRequester.requestFocus() },
            )
        }

        if (currentPinErrorText != null) {
            Text(
                text = currentPinErrorText,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier
                    .padding(top = 8.dp, bottom = 16.dp)
                    .testTag("pin_error_text"),
            )
        }

        PinTextField(
            state = newPinState,
            label = pluralStringResource(R.plurals.yk_fido_new_pin, count = minPinLen, minPinLen),
            showPin = showNewPin,
            onToggleShowPin = { showNewPin = !showNewPin },
            modifier =
            Modifier
                .fillMaxWidth()
                .focusRequester(newPinFocusRequester)
                .testTag("new_pin_input"),
            keyboardOptions =
            KeyboardOptions.Default.copy(
                imeAction = ImeAction.Next,
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.Password,
            ),
            onKeyboardAction = { repeatPinFocusRequester.requestFocus() },
        )

        PinTextField(
            state = repeatPinState,
            label = stringResource(R.string.yk_fido_repeat_pin),
            showPin = showRepeatPin,
            onToggleShowPin = { showRepeatPin = !showRepeatPin },
            modifier =
            Modifier
                .fillMaxWidth()
                .focusRequester(repeatPinFocusRequester)
                .testTag("repeat_pin_input"),
            keyboardOptions =
            KeyboardOptions.Default.copy(
                imeAction = ImeAction.Done,
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.Password,
            ),
            onKeyboardAction = submit,
        )

        if (newPinErrorText != null) {
            Text(
                text = newPinErrorText,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier
                    .padding(top = 8.dp)
                    .testTag("pin_error_text"),
            )
        }

        Row(
            modifier =
            Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
            horizontalArrangement = Arrangement.End,
        ) {
            Button(
                onClick = onCloseButtonClick,
                modifier = Modifier.padding(end = 8.dp),
            ) {
                Text(stringResource(R.string.yk_fido_cancel))
            }
            Button(
                onClick = submit,
                enabled = isPinValid(
                    newPinState.text.toString(),
                    repeatPinState.text.toString(),
                    minPinLen,
                ),
                modifier = Modifier.testTag(if (forceChangePin) "change_pin_button" else "create_pin_button"),
            ) {
                Text(
                    if (forceChangePin) {
                        stringResource(R.string.yk_fido_change_pin)
                    } else {
                        stringResource(R.string.yk_fido_create_pin)
                    },
                )
            }
        }
    }
}

private fun isPinValid(
    newPin: String,
    repeatPin: String,
    minPinLen: Int?,
): Boolean {
    return newPin.isNotEmpty() && newPin == repeatPin && newPin.length >= (minPinLen ?: 4)
    // Add more checks if needed (e.g., length, complexity)
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
internal fun PinTextField(
    state: TextFieldState,
    label: String,
    showPin: Boolean,
    onToggleShowPin: () -> Unit,
    modifier: Modifier = Modifier,
    keyboardOptions: KeyboardOptions,
    onKeyboardAction: () -> Unit,
) {
    OutlinedSecureTextField(
        state = state,
        label = { Text(label) },
        leadingIcon = {
            Icon(
                imageVector = Icons.Default.Password,
                contentDescription = stringResource(
                    R.string.yk_fido_icon_content_description_pin,
                ),
                tint = MaterialTheme.colorScheme.onBackground,
            )
        },
        trailingIcon = {
            IconButton(onClick = onToggleShowPin) {
                Icon(
                    imageVector = if (showPin) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                    contentDescription = if (showPin) {
                        stringResource(R.string.yk_fido_icon_content_description_hide_pin)
                    } else {
                        stringResource(R.string.yk_fido_icon_content_description_show_pin)
                    },
                )
            }
        },
        textObfuscationMode =
        if (showPin) {
            TextObfuscationMode.Visible
        } else {
            TextObfuscationMode.Hidden
        },
        modifier = modifier,
        keyboardOptions = keyboardOptions,
        onKeyboardAction = { onKeyboardAction() },
    )
}

@Composable
internal fun PinCreatedScreen(
    operation: FidoClientService.Operation,
    origin: String,
    onCloseButtonClick: () -> Unit,
    onContinue: () -> Unit,
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        contentHeight = 200.dp,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        Text(
            text = stringResource(R.string.yk_fido_pin_successfully_created),
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.padding(vertical = 24.dp),
        )
        Row(
            modifier =
            Modifier
                .fillMaxWidth()
                .padding(top = 16.dp),
            horizontalArrangement = Arrangement.End,
        ) {
            Button(
                onClick = onContinue,
            ) {
                Text(stringResource(R.string.yk_fido_continue_operation))
            }
        }
    }
}

@Composable
internal fun PinChangedScreen(
    operation: FidoClientService.Operation,
    origin: String,
    onCloseButtonClick: () -> Unit,
    onContinue: () -> Unit,
) {
    ContentWrapper(
        operation = operation,
        origin = origin,
        contentHeight = 200.dp,
        onCloseButtonClick = onCloseButtonClick,
    ) {
        Text(
            text = stringResource(R.string.yk_fido_pin_successfully_changed),
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.padding(vertical = 24.dp),
        )
        Row(
            modifier =
            Modifier
                .fillMaxWidth()
                .padding(top = 16.dp),
            horizontalArrangement = Arrangement.End,
        ) {
            Button(
                onClick = onContinue,
            ) {
                Text(stringResource(R.string.yk_fido_continue_operation))
            }
        }
    }
}

@DefaultPreview
@Composable
internal fun CreateChangePinPreview() {
    CreateChangePinScreen(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        onPinAction = { _, _ -> },
        onCloseButtonClick = {},
    )
}

@DefaultPreview
@Composable
internal fun ForceChangePinPreview() {
    CreateChangePinScreen(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        forceChangePin = true,
        onPinAction = { _, _ -> },
        onCloseButtonClick = {},
    )
}

@DefaultPreview
@Composable
internal fun CreateChangePinErrorPreview() {
    CreateChangePinScreen(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        error = Error.PinComplexityError,
        onPinAction = { _, _ -> },
        onCloseButtonClick = {},
    )
}

@DefaultPreview
@Composable
internal fun PinCreatedPreview() {
    PinCreatedScreen(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        onContinue = {},
        onCloseButtonClick = {},
    )
}

@DefaultPreview
@Composable
internal fun PinChangedPreview() {
    PinChangedScreen(
        operation = FidoClientService.Operation.MAKE_CREDENTIAL,
        origin = "example.com",
        onContinue = {},
        onCloseButtonClick = {},
    )
}

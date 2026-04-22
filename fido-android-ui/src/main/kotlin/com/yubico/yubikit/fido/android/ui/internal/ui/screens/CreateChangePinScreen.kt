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
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.outlined.Pin
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.ui.R
import com.yubico.yubikit.fido.android.ui.internal.FidoClientService
import com.yubico.yubikit.fido.android.ui.internal.ui.Error
import com.yubico.yubikit.fido.android.ui.internal.ui.components.ContentWrapper
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.DefaultPreview
import com.yubico.yubikit.fido.android.ui.internal.ui.theme.FidoAndroidTheme

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
        if (!forceChangePin) {
            // Create PIN layout
            Text(
                text = stringResource(R.string.yk_fido_set_pin_title),
                style = MaterialTheme.typography.headlineSmall,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("pin_info_text"),
            )
            Text(
                text = stringResource(R.string.yk_fido_set_pin_description),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                minLines = 2,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
            )

            PinTextFieldWithIcon(
                state = newPinState,
                label = pluralStringResource(R.plurals.yk_fido_new_pin, count = minPinLen, minPinLen),
                showPin = showNewPin,
                onToggleShowPin = { showNewPin = !showNewPin },
                modifier = Modifier
                    .padding(top = 16.dp, start = 16.dp, end = 16.dp)
                    .focusRequester(newPinFocusRequester),
                keyboardOptions = KeyboardOptions.Default.copy(
                    imeAction = ImeAction.Next,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Password,
                ),
                testTag = "new_pin_input",
                onKeyboardAction = { repeatPinFocusRequester.requestFocus() },
            )

            if (newPinErrorText != null) {
                Text(
                    text = newPinErrorText,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    minLines = 3,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp, start = 52.dp, end = 16.dp)
                        .testTag("pin_error_text"),
                )
            } else {
                Text(
                    text = stringResource(R.string.yk_fido_set_pin_requirements),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    minLines = 3,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp, start = 52.dp, end = 16.dp),
                )
            }

            PinTextFieldWithIcon(
                state = repeatPinState,
                label = stringResource(R.string.yk_fido_confirm_new_pin),
                showPin = showRepeatPin,
                onToggleShowPin = { showRepeatPin = !showRepeatPin },
                modifier = Modifier
                    .padding(top = 8.dp, start = 16.dp, end = 16.dp)
                    .focusRequester(repeatPinFocusRequester),
                keyboardOptions = KeyboardOptions.Default.copy(
                    imeAction = ImeAction.Done,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Password,
                ),
                testTag = "repeat_pin_input",
                onKeyboardAction = submit,
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                Button(
                    onClick = submit,
                    enabled = isPinValid(
                        newPinState.text.toString(),
                        repeatPinState.text.toString(),
                        minPinLen,
                    ),
                    modifier = Modifier.testTag("create_pin_button"),
                ) {
                    Text(stringResource(R.string.yk_fido_set_pin))
                }
            }
        } else {
            // Force change PIN layout
            Text(
                text = stringResource(R.string.yk_fido_change_pin_title),
                style = MaterialTheme.typography.headlineSmall,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("pin_info_text"),
            )
            Text(
                text = stringResource(R.string.yk_fido_info_force_change_pin),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                minLines = 2,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
            )

            PinTextFieldWithIcon(
                state = currentPinState,
                label = stringResource(R.string.yk_fido_current_pin),
                showPin = showCurrentPin,
                onToggleShowPin = { showCurrentPin = !showCurrentPin },
                modifier = Modifier
                    .padding(top = 16.dp, start = 16.dp, end = 16.dp)
                    .focusRequester(currentPinFocusRequester),
                keyboardOptions = KeyboardOptions.Default.copy(
                    imeAction = ImeAction.Next,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Password,
                ),
                testTag = "current_pin_input",
                onKeyboardAction = { newPinFocusRequester.requestFocus() },
            )

            if (currentPinErrorText != null) {
                Text(
                    text = currentPinErrorText,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp, start = 52.dp, end = 16.dp)
                        .testTag("pin_error_text"),
                )
            }

            PinTextFieldWithIcon(
                state = newPinState,
                label = pluralStringResource(R.plurals.yk_fido_new_pin, count = minPinLen, minPinLen),
                showPin = showNewPin,
                onToggleShowPin = { showNewPin = !showNewPin },
                modifier = Modifier
                    .padding(top = 8.dp, start = 16.dp, end = 16.dp)
                    .focusRequester(newPinFocusRequester),
                keyboardOptions = KeyboardOptions.Default.copy(
                    imeAction = ImeAction.Next,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Password,
                ),
                testTag = "new_pin_input",
                onKeyboardAction = { repeatPinFocusRequester.requestFocus() },
            )

            if (newPinErrorText != null) {
                Text(
                    text = newPinErrorText,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    minLines = 3,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp, start = 52.dp, end = 16.dp)
                        .testTag("pin_error_text"),
                )
            } else {
                Text(
                    text = stringResource(R.string.yk_fido_set_pin_requirements),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    minLines = 3,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp, start = 52.dp, end = 16.dp),
                )
            }

            PinTextFieldWithIcon(
                state = repeatPinState,
                label = stringResource(R.string.yk_fido_confirm_new_pin),
                showPin = showRepeatPin,
                onToggleShowPin = { showRepeatPin = !showRepeatPin },
                modifier = Modifier
                    .padding(top = 8.dp, start = 16.dp, end = 16.dp)
                    .focusRequester(repeatPinFocusRequester),
                keyboardOptions = KeyboardOptions.Default.copy(
                    imeAction = ImeAction.Done,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Password,
                ),
                testTag = "repeat_pin_input",
                onKeyboardAction = submit,
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                Button(
                    onClick = submit,
                    enabled = isPinValid(
                        newPinState.text.toString(),
                        repeatPinState.text.toString(),
                        minPinLen,
                    ),
                    modifier = Modifier.testTag("change_pin_button"),
                ) {
                    Text(stringResource(R.string.yk_fido_change_pin))
                }
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
private fun PinTextFieldWithIcon(
    state: TextFieldState,
    label: String,
    showPin: Boolean,
    onToggleShowPin: () -> Unit,
    modifier: Modifier = Modifier,
    keyboardOptions: KeyboardOptions,
    onKeyboardAction: () -> Unit,
    testTag: String,
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = Icons.Outlined.Pin,
            contentDescription = stringResource(R.string.yk_fido_icon_content_description_pin),
            tint = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.size(24.dp),
        )
        Spacer(modifier = Modifier.width(12.dp))
        OutlinedSecureTextField(
            state = state,
            label = { Text(label) },
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
            textObfuscationMode = if (showPin) TextObfuscationMode.Visible else TextObfuscationMode.Hidden,
            modifier = Modifier.weight(1f).testTag(testTag),
            keyboardOptions = keyboardOptions,
            onKeyboardAction = { onKeyboardAction() },
        )
    }
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
            text = stringResource(R.string.yk_fido_pin_successfully_set),
            style = MaterialTheme.typography.headlineSmall,
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
            style = MaterialTheme.typography.headlineSmall,
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

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true, showSystemUi = true, device = Devices.PIXEL_4)
@Composable
private fun CreatePinInBottomSheetPreview() {
    FidoAndroidTheme {
        ModalBottomSheet(
            contentWindowInsets = { WindowInsets(0) },
            dragHandle = {},
            sheetState = rememberModalBottomSheetState(),
            onDismissRequest = {},
        ) {
            CreateChangePinScreen(
                operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                origin = "example.com",
                onPinAction = { _, _ -> },
                onCloseButtonClick = {},
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(showBackground = true, showSystemUi = true, device = Devices.PIXEL_4)
@Composable
private fun ChangePinInBottomSheetPreview() {
    FidoAndroidTheme {
        ModalBottomSheet(
            contentWindowInsets = { WindowInsets(0) },
            dragHandle = {},
            sheetState = rememberModalBottomSheetState(),
            onDismissRequest = {},
        ) {
            CreateChangePinScreen(
                operation = FidoClientService.Operation.MAKE_CREDENTIAL,
                forceChangePin = true,
                origin = "example.com",
                onPinAction = { _, _ -> },
                onCloseButtonClick = {},
            )
        }
    }
}

@DefaultPreview
@Composable
internal fun CreateChangePinPreview() {
    FidoAndroidTheme {
        CreateChangePinScreen(
            operation = FidoClientService.Operation.MAKE_CREDENTIAL,
            origin = "example.com",
            onPinAction = { _, _ -> },
            onCloseButtonClick = {},
        )
    }
}

@DefaultPreview
@Composable
internal fun ForceChangePinPreview() {
    FidoAndroidTheme {
        CreateChangePinScreen(
            operation = FidoClientService.Operation.MAKE_CREDENTIAL,
            origin = "example.com",
            forceChangePin = true,
            onPinAction = { _, _ -> },
            onCloseButtonClick = {},
        )
    }
}

@DefaultPreview
@Composable
internal fun CreateChangePinErrorPreview() {
    FidoAndroidTheme {
        CreateChangePinScreen(
            operation = FidoClientService.Operation.MAKE_CREDENTIAL,
            origin = "example.com",
            error = Error.PinComplexityError,
            onPinAction = { _, _ -> },
            onCloseButtonClick = {},
        )
    }
}

@DefaultPreview
@Composable
internal fun PinCreatedPreview() {
    FidoAndroidTheme {
        PinCreatedScreen(
            operation = FidoClientService.Operation.MAKE_CREDENTIAL,
            origin = "example.com",
            onContinue = {},
            onCloseButtonClick = {},
        )
    }
}

@DefaultPreview
@Composable
internal fun PinChangedPreview() {
    FidoAndroidTheme {
        PinChangedScreen(
            operation = FidoClientService.Operation.MAKE_CREDENTIAL,
            origin = "example.com",
            onContinue = {},
            onCloseButtonClick = {},
        )
    }
}

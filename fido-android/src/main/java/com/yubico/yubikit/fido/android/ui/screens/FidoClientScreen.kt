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

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.android.FidoClientService
import com.yubico.yubikit.fido.android.MainViewModel
import com.yubico.yubikit.fido.android.ui.Error
import com.yubico.yubikit.fido.android.ui.UiState
import com.yubico.yubikit.fido.client.ClientError
import com.yubico.yubikit.fido.client.MultipleAssertionsAvailable
import com.yubico.yubikit.fido.client.PinInvalidClientError
import com.yubico.yubikit.fido.client.PinRequiredClientError
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity

@Composable
fun FidoClientUi(
    viewModel: MainViewModel,
    operation: FidoClientService.Operation,
    isUsb: Boolean,
    isNfcAvailable: Boolean,
    rpId: String,
    request: String,
    clientDataHash: ByteArray?,
    fidoClientService: FidoClientService = remember { FidoClientService() },
    onResult: (PublicKeyCredential) -> Unit = {},
    onShowNfcGuideClick: () -> Unit,
    onCloseButtonClick: () -> Unit
) {
    var result: PublicKeyCredential? by remember { mutableStateOf(null) }
    var pinValue: String? by remember { mutableStateOf(null) }
    var newPinValue: String? by remember { mutableStateOf(null) }
    var retryOperation by remember { mutableStateOf(false) }
    var tapAgain by remember { mutableStateOf(false) }
    var multipleAssertions: MultipleAssertionsAvailable? by remember { mutableStateOf(null) }

    val uiState = produceState<UiState>(
        initialValue = UiState.WaitingForKey,
        key1 = retryOperation,
        key2 = multipleAssertions
    ) {
        try {
            if (result != null) {
                fidoClientService.waitForKeyRemoval()
                onResult(result!!)
                return@produceState
            }

            multipleAssertions?.let { assertions ->
                val users = try {
                    assertions.getUsers()
                } catch (_: Exception) {
                    emptyList<PublicKeyCredentialUserEntity>()
                }
                value = UiState.MultipleAssertions(users) {
                    result = assertions.select(it)
                    multipleAssertions = null
                    retryOperation = !retryOperation
                }
                return@produceState
            }

            if (tapAgain) {
                value = UiState.WaitingForKeyAgain
                tapAgain = false
            } else {
                value = UiState.WaitingForKey
            }

            newPinValue?.let { newPin ->
                pinValue?.let { pin ->
                    // TODO change pin
                } ?: run {
                    // create pin
                    fidoClientService.createPin(newPin)
                        .fold(
                            {
                                // setting the PIN succeeded, will continue with original operation
                                pinValue = newPin
                                value = UiState.PinCreated
                            },
                            {
                                val createPinError = when (it) {
                                    is ClientError -> Error.PinComplexityError
                                    else -> Error.UnknownError("Creating Pin Failed")
                                }
                                value = UiState.PinNotSetError(createPinError)
                            }
                        ).also {
                            newPinValue = null
                        }
                    return@produceState
                }
            }

            fidoClientService.performOperation(pinValue, operation, rpId, clientDataHash, request) {
                value = if (isUsb) UiState.TouchKey else UiState.Processing
            }
                .fold(onSuccess = {
                    result = it
                    value = UiState.Success
                    retryOperation = !retryOperation
                    return@produceState
                }, onFailure = { error ->
                    val errorState = when (error) {
                        is MultipleAssertionsAvailable -> {
                            multipleAssertions = error
                            return@produceState
                        }

                        is PinRequiredClientError -> Error.PinRequiredError
                        is PinInvalidClientError -> Error.IncorrectPinError(
                            error.pinRetries
                        )

                        is ClientError -> {
                            when((error.cause as? CtapException)?.ctapError) {
                                CtapException.ERR_PIN_BLOCKED -> Error.PinBlockedError
                                CtapException.ERR_PIN_AUTH_BLOCKED -> Error.PinAuthBlockedError
                                CtapException.ERR_PIN_INVALID -> Error.IncorrectPinError(null)
                                CtapException.ERR_PIN_NOT_SET -> Error.PinNotSetError
                                CtapException.ERR_PIN_POLICY_VIOLATION -> Error.IncorrectPinError(null)
                                // others will get an Error view with textual description of the error
                                else -> Error.OperationError(error.cause)
                            }
                        }

                        else -> Error.UnknownError(
                            error.message
                        )
                    }

                    value = when (errorState) {
                        is Error.PinRequiredError,
                        is Error.PinBlockedError,
                        is Error.PinAuthBlockedError,
                        is Error.IncorrectPinError -> {
                            // Show PIN entry screen with error
                            UiState.WaitingForPinEntry(errorState)
                        }

                        is Error.PinNotSetError -> {
                            // Ask the user to create a PIN
                            UiState.PinNotSetError()
                        }

                        else -> {
                            UiState.OperationError(errorState)
                        }
                    }
                    return@produceState
                })
        } catch (e: Exception) {
            value = UiState.OperationError(
                Error.UnknownError(
                    e.message
                )
            )
        }
    }

    Column(
        modifier = Modifier
            .padding(
                top = 16.dp,
                start = 16.dp,
                end = 16.dp,
                bottom = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()
            ),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        AnimatedContent(
            targetState = uiState.value,
            label = "FidoClientUi",
            transitionSpec = {
                fadeIn() togetherWith fadeOut()
            }
        ) { state ->
            when (state) {

                is UiState.WaitingForKey -> {
                    TapOrInsertSecurityKey(
                        operation = operation,
                        isNfcAvailable = isNfcAvailable,
                        origin = rpId,
                        onCloseButtonClick = onCloseButtonClick,
                        onShowNfcGuideClick = onShowNfcGuideClick
                    )
                }

                is UiState.WaitingForKeyAgain -> {
                    TapAgainSecurityKey(
                        operation = operation,
                        origin = rpId,
                        onCloseButtonClick = onCloseButtonClick
                    )
                }

                is UiState.WaitingForPinEntry -> {
                    EnterPin(
                        operation = operation,
                        origin = rpId,
                        error = state.error,
                        pin = pinValue ?: "",
                        onCloseButtonClick = onCloseButtonClick
                    ) {
                        pinValue = it.ifEmpty {
                            null
                        }
                        retryOperation = !retryOperation
                        tapAgain = true
                    }
                }

                is UiState.PinNotSetError -> {
                    CreatePinScreen(
                        operation = operation,
                        origin = rpId,
                        error = state.error,
                        minPinLen = viewModel.info?.minPinLength ?: DEFAULT_MIN_PIN_LENGTH,
                        onCloseButtonClick = onCloseButtonClick,
                    ) {
                        newPinValue = it.ifEmpty { null }
                        retryOperation = !retryOperation
                        tapAgain = true
                    }
                }

                is UiState.PinCreated -> {
                    PinCreatedScreen(
                        operation = operation,
                        origin = rpId,
                        onCloseButtonClick = onCloseButtonClick,
                    ) {
                        retryOperation = !retryOperation
                        tapAgain = true
                    }
                }

                is UiState.Processing -> {
                    Processing(operation = operation, origin = rpId) {}
                }

                is UiState.TouchKey -> {
                    TouchTheSecurityKey(operation = operation, origin = rpId) {}
                }

                is UiState.Success -> {
                    SuccessView(operation = operation, origin = rpId)
                }

                is UiState.MultipleAssertions -> {
                    MultipleAssertionsScreen(
                        operation = operation,
                        origin = rpId,
                        onCloseButtonClick = onCloseButtonClick,
                        users = state.users,
                        onSelect = state.onSelect
                    )
                }

                is UiState.OperationError -> {
                    ErrorView(
                        operation = operation,
                        origin = rpId,
                        error = state.error
                    ) {
                        pinValue = null
                        retryOperation = !retryOperation
                    }
                }
            }
        }

    }
}

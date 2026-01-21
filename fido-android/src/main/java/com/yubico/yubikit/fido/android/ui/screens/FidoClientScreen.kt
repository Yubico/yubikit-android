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

package com.yubico.yubikit.fido.android.ui.screens

import androidx.activity.compose.BackHandler
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.fido.android.FidoClientService
import com.yubico.yubikit.fido.android.MainViewModel
import com.yubico.yubikit.fido.android.Origin
import com.yubico.yubikit.fido.android.ui.UiState
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import org.slf4j.Logger
import org.slf4j.LoggerFactory

@Composable
fun FidoClientUi(
    viewModel: MainViewModel,
    operation: FidoClientService.Operation,
    isNfcAvailable: Boolean,
    origin: Origin,
    request: String,
    clientDataHash: ByteArray?,
    fidoClientService: FidoClientService,
    onResult: (PublicKeyCredential) -> Unit = {},
    onCloseButtonClick: () -> Unit,
) {
    val uiState by viewModel.uiState.collectAsState()
    val latestOnResult = remember(onResult) { onResult }
    val handleCloseButton: () -> Unit = {
        fidoClientService.cancelOngoingOperation()
        onCloseButtonClick()
    }
    val logger: Logger = LoggerFactory.getLogger("FidoUiClient")

    BackHandler {
        handleCloseButton()
    }

    LaunchedEffect(Unit) {
        logger.trace(
            "Start operation: {} on {}. Request: {}",
            operation.name,
            origin,
            request,
        )
        viewModel.startFidoOperation(
            fidoClientService,
            operation,
            origin,
            request,
            clientDataHash,
            latestOnResult,
        )
    }

    Column(
        modifier =
        Modifier
            .padding(
                top = 16.dp,
                start = 16.dp,
                end = 16.dp,
                bottom = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding(),
            ),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        LaunchedEffect(uiState) {
            logger.debug("Current state: {}", uiState)
        }

        AnimatedContent(
            targetState = uiState,
            label = "FidoClientUi",
            transitionSpec = {
                fadeIn() togetherWith fadeOut()
            },
        ) { state ->
            when (state) {
                is UiState.WaitingForKey -> {
                    TapOrInsertSecurityKey(
                        operation = operation,
                        isNfcAvailable = isNfcAvailable,
                        origin = origin.callingApp,
                        onCloseButtonClick = handleCloseButton,
                    )
                }

                is UiState.WaitingForKeyAgain -> {
                    TapAgainSecurityKey(
                        operation = operation,
                        origin = origin.callingApp,
                        onCloseButtonClick = handleCloseButton,
                    )
                }

                is UiState.WaitingForPinEntry -> {
                    EnterPin(
                        operation = operation,
                        origin = origin.callingApp,
                        error = state.error,
                        pin = viewModel.lastEnteredPin,
                        onCloseButtonClick = handleCloseButton,
                    ) {
                        viewModel.onEnterPin(it)
                    }
                }

                is UiState.WaitingForUvEntry -> {
                    MatchFingerprint(
                        operation = operation,
                        origin = origin.callingApp,
                        error = state.error,
                        onCloseButtonClick = handleCloseButton,
                    )

                    if (state.error != null) {
                        LaunchedEffect(state) {
                            viewModel.onUvMatchError()
                        }
                    }
                }

                is UiState.PinNotSetError -> {
                    CreatePinScreen(
                        operation = operation,
                        origin = origin.callingApp,
                        error = state.error,
                        minPinLen = viewModel.info?.minPinLength ?: DEFAULT_MIN_PIN_LENGTH,
                        onCloseButtonClick = handleCloseButton,
                    ) { newPin ->
                        viewModel.onCreatePin(newPin)
                    }
                }

                is UiState.ForcePinChangeError -> {
                    ForceChangePinScreen(
                        operation = operation,
                        origin = origin.callingApp,
                        error = state.error,
                        minPinLen = viewModel.info?.minPinLength ?: DEFAULT_MIN_PIN_LENGTH,
                        onCloseButtonClick = handleCloseButton,
                    ) { currentPin, newPin ->
                        viewModel.onChangePin(currentPin, newPin)
                    }
                }

                is UiState.PinCreated -> {
                    PinCreatedScreen(
                        operation = operation,
                        origin = origin.callingApp,
                        onCloseButtonClick = handleCloseButton,
                    ) {
                        viewModel.onPinCreatedConfirmation()
                    }
                }

                is UiState.PinChanged -> {
                    PinChangedScreen(
                        operation = operation,
                        origin = origin.callingApp,
                        onCloseButtonClick = handleCloseButton,
                    ) {
                        viewModel.onPinChangedConfirmation()
                    }
                }

                is UiState.Processing -> {
                    Processing(
                        operation = operation,
                        origin = origin.callingApp,
                        onCloseButtonClick = handleCloseButton,
                    )
                }

                is UiState.TouchKey -> {
                    TouchTheSecurityKey(
                        operation = operation,
                        origin = origin.callingApp,
                        onCloseButtonClick = handleCloseButton,
                    )
                }

                is UiState.Success -> {
                    SuccessView(operation = operation, origin = origin.callingApp)
                }

                is UiState.MultipleAssertions -> {
                    MultipleAssertionsScreen(
                        operation = operation,
                        origin = origin.callingApp,
                        onCloseButtonClick = handleCloseButton,
                        users = state.users,
                        onSelect = state.onSelect,
                    )
                }

                is UiState.OperationError -> {
                    ErrorView(
                        operation = operation,
                        origin = origin.callingApp,
                        error = state.error,
                    ) {
                        viewModel.onErrorConfirmation()
                    }
                }
            }
        }
    }
}

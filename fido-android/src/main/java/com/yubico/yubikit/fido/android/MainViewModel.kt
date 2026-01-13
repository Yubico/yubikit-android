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

package com.yubico.yubikit.fido.android

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.core.util.Result
import com.yubico.yubikit.fido.android.YubiKitFidoClient.Companion.extensions
import com.yubico.yubikit.fido.android.ui.Error
import com.yubico.yubikit.fido.android.ui.UiState
import com.yubico.yubikit.fido.client.AuthInvalidClientError
import com.yubico.yubikit.fido.client.ClientError
import com.yubico.yubikit.fido.client.Ctap2Client
import com.yubico.yubikit.fido.client.MultipleAssertionsAvailable
import com.yubico.yubikit.fido.client.PinRequiredClientError
import com.yubico.yubikit.fido.client.WebAuthnClient
import com.yubico.yubikit.fido.ctap.BioEnrollment
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

typealias YubiKeyAction = suspend (Result<YubiKeyDevice, Exception>) -> Unit

class MainViewModel : ViewModel() {
    private val nfcAvailable = MutableLiveData(false)
    val isNfcAvailable: LiveData<Boolean> = nfcAvailable

    var info: Ctap2Session.InfoData? = null

    private val _device = MutableLiveData<YubiKeyDevice?>()
    val device: LiveData<YubiKeyDevice?> = _device

    private val pendingYubiKeyAction = MutableLiveData<YubiKeyAction?>()

    private val _uiState = MutableStateFlow<UiState>(UiState.WaitingForKey)
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private var result: PublicKeyCredential? = null
    private var pinValue: CharArray? = null
    private var newPinValue: CharArray? = null
    private var multipleAssertions: MultipleAssertionsAvailable? = null
    private var uvFallback: Boolean = false

    private val logger: Logger = LoggerFactory.getLogger(MainViewModel::class.java)

    // Store last parameters for retry
    private var lastFidoClientService: FidoClientService? = null
    private var lastOperation: FidoClientService.Operation? = null
    private var lastRpId: String? = null
    private var lastRequest: String? = null
    private var lastClientDataHash: ByteArray? = null
    private var lastOnResult: ((PublicKeyCredential) -> Unit)? = null

    var lastEnteredPin: CharArray? = null
        private set

    fun setLastEnteredPin(pin: CharArray) {
        lastEnteredPin = pin.clone()
    }

    fun clearLastEnteredPin() {
        lastEnteredPin?.fill('\u0000')
        lastEnteredPin = null
    }

    fun setNfcAvailable(value: Boolean) {
        nfcAvailable.postValue(value)
    }

    suspend fun provideYubiKey(device: YubiKeyDevice) {
        pendingYubiKeyAction.value?.let {
            pendingYubiKeyAction.postValue(null)
            it.invoke(Result.success(device))
        }
        (device as? UsbYubiKeyDevice?)?.setOnClosed {
            _device.postValue(null)
        }
        _device.postValue(device)
    }

    suspend fun waitForKeyRemoval() {
        delay(250)
        suspendCoroutine { continuation ->
            when (val dev = _device.value) {
                is NfcYubiKeyDevice ->
                    dev.remove {
                        continuation.resume(Unit)
                    }

                else -> {
                    continuation.resume(Unit)
                }
            }
        }
    }

    /**
     * Requests a WebAuthn client, and uses it to produce some result
     */
    suspend fun <T> useWebAuthn(action: (WebAuthnClient) -> T): kotlin.Result<T> =
        runCatching {
            val device =
                (_device.value as? UsbYubiKeyDevice)
                    ?: awaitPendingYubiKeyDevice()
            withWebAuthnClient(device, action)
        }

    private suspend fun awaitPendingYubiKeyDevice(): YubiKeyDevice =
        suspendCoroutine { cont ->
            pendingYubiKeyAction.postValue { result ->
                cont.resume(result.value)
            }
        }

    private suspend fun <T> withWebAuthnClient(
        device: YubiKeyDevice,
        action: (WebAuthnClient) -> T,
    ): T =
        withContext(Dispatchers.IO) {
            WebAuthnClient.create(device, extensions).use { client ->
                if (client is Ctap2Client) info = client.session.cachedInfo
                action(client)
            }
        }

    private fun deliverResult(
        credential: PublicKeyCredential,
        onResult: (PublicKeyCredential) -> Unit,
    ) {
        _uiState.value = UiState.Success
        onResult(credential)
        result = null
    }

    private fun showMultipleAssertions(
        assertions: MultipleAssertionsAvailable,
        onResult: (PublicKeyCredential) -> Unit,
    ) {
        multipleAssertions = assertions
        val users =
            runCatching { assertions.getUsers() }
                .getOrElse { emptyList() }

        _uiState.value =
            UiState.MultipleAssertions(users) { user ->
                assertions.select(user).let { selected ->
                    result = selected
                    deliverResult(selected, onResult)
                }
                multipleAssertions = null
            }
    }

    private fun signalRetry(forUsb: Boolean = true) {
        if (_device.value?.transport == Transport.NFC) {
            // we ask the user to tap the key again
            _uiState.value = UiState.WaitingForKeyAgain
        } else {
            if (forUsb) {
                // show the touch key with delay
                setUiStateWithDelay(UiState.TouchKey)
            }
        }
        runFidoOperation()
    }

    private fun runFidoOperation() {
        startFidoOperation(
            lastFidoClientService!!,
            lastOperation!!,
            lastRpId!!,
            lastRequest!!,
            lastClientDataHash,
            lastOnResult!!,
        )
    }

    fun startFidoOperation(
        fidoClientService: FidoClientService,
        operation: FidoClientService.Operation,
        rpId: String,
        request: String,
        clientDataHash: ByteArray?,
        onResult: (PublicKeyCredential) -> Unit,
    ) {
        logger.trace(
            "Start operation: {} on {}. Request: {}",
            operation.name,
            rpId,
            request,
        )

        // Save parameters for retry
        lastFidoClientService = fidoClientService
        lastOperation = operation
        lastRpId = rpId
        lastRequest = request
        lastClientDataHash = clientDataHash
        lastOnResult = onResult

        viewModelScope.launch {
            try {
                result?.let {
                    deliverResult(it, onResult)
                    return@launch
                }
                multipleAssertions?.let {
                    showMultipleAssertions(it, onResult)
                    return@launch
                }

                newPinValue?.let { newPin ->
                    val currentPinValue = pinValue?.clone()
                    if (currentPinValue != null) {
                        // change pin
                        fidoClientService.changePin(currentPinValue, newPin)
                            .fold(
                                {
                                    pinValue = newPin.clone()
                                    _uiState.value = UiState.PinChanged
                                },
                                {
                                    val forcePinChangeError =
                                        when (it) {
                                            // there can be various errors during force change pin
                                            is AuthInvalidClientError ->
                                                when (it.authType) {
                                                    AuthInvalidClientError.AuthType.PIN -> Error.IncorrectPinError(it.retries)
                                                    AuthInvalidClientError.AuthType.UV -> Error.IncorrectUvError(it.retries)
                                                }
                                            is ClientError ->
                                                when (it.errorCode) {
                                                    ClientError.Code.BAD_REQUEST ->
                                                        when ((it.cause as? CtapException)?.ctapError) {
                                                            CtapException.ERR_PIN_BLOCKED -> Error.PinBlockedError
                                                            CtapException.ERR_PIN_AUTH_BLOCKED -> Error.PinAuthBlockedError
                                                            CtapException.ERR_PIN_NOT_SET -> Error.PinNotSetError
                                                            CtapException.ERR_PIN_POLICY_VIOLATION ->
                                                                when (info?.forcePinChange) {
                                                                    true -> Error.PinComplexityError
                                                                    else -> Error.IncorrectPinError(null)
                                                                }
                                                            else -> Error.UnknownError("Changing pin Failed")
                                                        }
                                                    else -> Error.UnknownError("Changing pin Failed")
                                                }
                                            else -> Error.UnknownError("Changing pin Failed")
                                        }
                                    _uiState.value = UiState.ForcePinChangeError(forcePinChangeError)
                                },
                            ).also {
                                newPinValue?.fill('\u0000')
                                newPinValue = null
                                pinValue?.fill('\u0000')
                                pinValue = null
                            }
                    } else {
                        // create pin
                        fidoClientService.createPin(newPin)
                            .fold(
                                {
                                    pinValue = newPin.clone()
                                    _uiState.value = UiState.PinCreated
                                },
                                {
                                    val createPinError =
                                        when (it) {
                                            is ClientError -> Error.PinComplexityError
                                            else -> Error.UnknownError("Creating Pin Failed")
                                        }
                                    _uiState.value = UiState.PinNotSetError(createPinError)
                                },
                            ).also {
                                newPinValue?.fill('\u0000')
                                newPinValue = null
                            }
                    }
                    return@launch
                }

                fidoClientService.performOperation(
                    pinValue,
                    operation,
                    rpId,
                    clientDataHash,
                    request,
                ) {
                    // this code is executed when a connection is established
                    _uiState.value = info?.let {
                        val bioEnrollmentConfigured = BioEnrollment.isConfigured(it)
                        val isUsb = _device.value?.transport == Transport.USB
                        if (bioEnrollmentConfigured && !uvFallback) {
                            UiState.WaitingForUvEntry(
                                (_uiState.value as? UiState.WaitingForUvEntry)?.error,
                            )
                        } else if (isUsb) {
                            UiState.TouchKey
                        } else {
                            UiState.Processing
                        }
                    } ?: UiState.WaitingForKey
                }
                    .fold(onSuccess = {
                        result = it
                        deliverResult(it, onResult)
                    }, onFailure = { error ->
                        cancelUiStateTimer()
                        if (error is MultipleAssertionsAvailable) {
                            showMultipleAssertions(error, onResult)
                            return@launch
                        }

                        val errorState =
                            when (error) {
                                is PinRequiredClientError -> Error.PinRequiredError
                                is AuthInvalidClientError ->
                                    when (error.authType) {
                                        AuthInvalidClientError.AuthType.PIN -> Error.IncorrectPinError(error.retries)
                                        AuthInvalidClientError.AuthType.UV -> Error.IncorrectUvError(error.retries)
                                    }

                                is ClientError -> {
                                    when (error.errorCode) {
                                        ClientError.Code.CONFIGURATION_UNSUPPORTED ->
                                            when ((error.cause as? CtapException)?.ctapError) {
                                                CtapException.ERR_KEY_STORE_FULL ->
                                                    Error.OperationError(
                                                        error.cause,
                                                    )

                                                else -> Error.DeviceNotConfiguredError
                                            }

                                        else ->
                                            when ((error.cause as? CtapException)?.ctapError) {
                                                CtapException.ERR_PIN_BLOCKED -> Error.PinBlockedError
                                                CtapException.ERR_PIN_AUTH_BLOCKED -> Error.PinAuthBlockedError

                                                CtapException.ERR_PIN_NOT_SET -> Error.PinNotSetError
                                                CtapException.ERR_PIN_POLICY_VIOLATION ->
                                                    when (info?.forcePinChange) {
                                                        true -> Error.ForcePinChangeError(null)
                                                        else -> Error.IncorrectPinError(null)
                                                    }

                                                CtapException.ERR_UV_BLOCKED,
                                                CtapException.ERR_PUAT_REQUIRED,
                                                -> Error.UvBlockedError

                                                else -> Error.OperationError(error.cause)
                                            }
                                    }
                                }

                                else -> Error.UnknownError(error.message)
                            }
                        // handle the error by advancing to the next UI state
                        _uiState.value =
                            when (errorState) {
                                is Error.PinRequiredError,
                                is Error.PinBlockedError,
                                is Error.PinAuthBlockedError,
                                is Error.IncorrectPinError,
                                -> UiState.WaitingForPinEntry(errorState)

                                is Error.UvBlockedError -> {
                                    uvFallback = true
                                    UiState.WaitingForPinEntry(errorState)
                                }

                                is Error.IncorrectUvError -> UiState.WaitingForUvEntry(errorState)
                                is Error.PinNotSetError -> UiState.PinNotSetError()
                                is Error.ForcePinChangeError -> UiState.ForcePinChangeError()
                                else -> UiState.OperationError(errorState)
                            }
                        return@launch
                    })
            } catch (e: Exception) {
                _uiState.value = UiState.OperationError(Error.UnknownError(e.message))
            }
        }
    }

    // executed after UV error (fingerprint did not match)
    fun onUvMatchError() {
        runFidoOperation()
    }

    // executed after the user entered PIN and taps the "Continue" button
    fun onEnterPin(pin: CharArray) {
        setLastEnteredPin(pin)
        pinValue?.fill('\u0000')
        pinValue = pin.clone()
        pin.fill('\u0000')
        signalRetry(forUsb = uvFallback)
    }

    // executed after the user taps the "Create PIN" button
    fun onCreatePin(pin: CharArray) {
        newPinValue?.fill('\u0000')
        newPinValue = pin.clone()
        pin.fill('\u0000')
        // we don't setup USB because there is no
        // need for touch. The touch will be required after onPinCreatedConfirmation
        signalRetry(forUsb = false)
    }

    // executed after the user taps the "Create PIN" button
    fun onChangePin(
        currentPin: CharArray,
        newPin: CharArray,
    ) {
        newPinValue?.fill('\u0000')
        newPinValue = newPin.clone()
        newPin.fill('\u0000')
        pinValue?.fill('\u0000')
        pinValue = currentPin.clone()
        currentPin.fill('\u0000')
        // we don't setup USB because there is no
        // need for touch. The touch will be required after onPinCreatedConfirmation
        signalRetry(forUsb = false)
    }

    // executed after the user taps the "Continue" button in PIN created screen
    fun onPinCreatedConfirmation() {
        signalRetry()
    }

    // executed after the user taps the "Continue" button in PIN changed screen
    fun onPinChangedConfirmation() {
        signalRetry()
    }

    // executed after the user taps the "Retry" button in Error screen
    fun onErrorConfirmation() {
        clearLastEnteredPin()
        pinValue?.fill('\u0000')
        pinValue = null
        uvFallback = false
        signalRetry()
    }

    // job for changing the uiState with delay
// used currently for setting TouchKey state when USB key is connected
// default delay is value which worked best
    private var uiStateTimerJob: Job? = null

    fun setUiStateWithDelay(
        newState: UiState,
        delayMillis: Long = 500,
    ) {
        uiStateTimerJob?.cancel()
        uiStateTimerJob =
            viewModelScope.launch {
                delay(delayMillis)
                _uiState.value = newState
            }
    }

    fun cancelUiStateTimer() {
        uiStateTimerJob?.cancel()
        uiStateTimerJob = null
    }
}

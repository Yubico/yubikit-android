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
import com.yubico.yubikit.fido.client.BasicWebAuthnClient
import com.yubico.yubikit.fido.client.ClientError
import com.yubico.yubikit.fido.client.MultipleAssertionsAvailable
import com.yubico.yubikit.fido.client.PinInvalidClientError
import com.yubico.yubikit.fido.client.PinRequiredClientError
import com.yubico.yubikit.fido.client.UvInvalidClientError
import com.yubico.yubikit.fido.ctap.BioEnrollment
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

typealias YubiKeyAction = suspend (Result<YubiKeyDevice, Exception>) -> Unit

class MainViewModel : ViewModel() {

    private val _nfcAvailable = MutableLiveData(false)
    val isNfcAvailable: LiveData<Boolean> = _nfcAvailable

    var info: Ctap2Session.InfoData? = null

    private val _device = MutableLiveData<YubiKeyDevice?>()
    val device: LiveData<YubiKeyDevice?> = _device

    private val _pendingYubiKeyAction = MutableLiveData<YubiKeyAction?>()

    private val _uiState = MutableStateFlow<UiState>(UiState.WaitingForKey)
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private var result: PublicKeyCredential? = null
    private var pinValue: String? = null
    private var newPinValue: String? = null
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
    private var lastEnteredPin: String = ""

    fun setNfcAvailable(value: Boolean) {
        _nfcAvailable.postValue(value)
    }

    suspend fun provideYubiKey(device: YubiKeyDevice) {
        _pendingYubiKeyAction.value?.let {
            _pendingYubiKeyAction.postValue(null)
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
                is NfcYubiKeyDevice -> dev.remove {
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
    suspend fun <T> useWebAuthn(
        action: (BasicWebAuthnClient) -> T
    ): kotlin.Result<T> {
        // directly use the device if it is a USB YubiKey
        (_device.value as? UsbYubiKeyDevice?)?.let { usbDevice ->
            return suspendCoroutine { inner ->
                Ctap2Session.create(usbDevice) { result ->
                    inner.resume(runCatching {
                        info = result.value.cachedInfo
                        extensions?.let { ext ->
                            action.invoke(BasicWebAuthnClient(result.value, ext))
                        } ?: action.invoke(BasicWebAuthnClient(result.value))
                    })
                }
            }
        }
        return suspendCoroutine { outer ->
            _pendingYubiKeyAction.postValue { result ->
                outer.resumeWith(runCatching {
                    suspendCoroutine { inner ->
                        Ctap2Session.create(result.value) { result ->
                            inner.resume(runCatching {
                                info = result.value.cachedInfo
                                extensions?.let { ext ->
                                    action.invoke(BasicWebAuthnClient(result.value, ext))
                                } ?: action.invoke(BasicWebAuthnClient(result.value))
                            })
                        }
                    }
                })
            }
        }
    }

    private fun deliverResult(
        credential: PublicKeyCredential,
        onResult: (PublicKeyCredential) -> Unit
    ) {
        _uiState.value = UiState.Success
        onResult(credential)
        result = null
    }

    private fun showMultipleAssertions(
        assertions: MultipleAssertionsAvailable,
        onResult: (PublicKeyCredential) -> Unit
    ) {
        multipleAssertions = assertions
        val users = runCatching { assertions.getUsers() }
            .getOrElse { emptyList<PublicKeyCredentialUserEntity>() }

        _uiState.value = UiState.MultipleAssertions(users) { user ->
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
            lastOnResult!!
        )
    }

    fun startFidoOperation(
        fidoClientService: FidoClientService,
        operation: FidoClientService.Operation,
        rpId: String,
        request: String,
        clientDataHash: ByteArray?,
        onResult: (PublicKeyCredential) -> Unit
    ) {

        logger.trace(
            "Start operation: {} on {}. Request: {}",
            operation.name,
            rpId,
            request
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
                result?.let { deliverResult(it, onResult); return@launch }
                multipleAssertions?.let { showMultipleAssertions(it, onResult); return@launch }

                newPinValue?.let { newPin ->
                    pinValue?.let { pin ->
                        // TODO change pin
                    } ?: run {
                        fidoClientService.createPin(newPin)
                            .fold(
                                {
                                    pinValue = newPin
                                    _uiState.value = UiState.PinCreated
                                },
                                {
                                    val createPinError = when (it) {
                                        is ClientError -> Error.PinComplexityError
                                        else -> Error.UnknownError("Creating Pin Failed")
                                    }
                                    _uiState.value = UiState.PinNotSetError(createPinError)
                                }
                            ).also {
                                newPinValue = null
                            }
                        return@launch
                    }
                }
                fidoClientService.performOperation(
                    pinValue,
                    operation,
                    rpId,
                    clientDataHash,
                    request
                ) {
                    _uiState.value = info?.let {
                        val bioEnrollmentConfigured = BioEnrollment.isConfigured(it)
                        val isUsb = _device.value?.transport == Transport.USB
                        if (bioEnrollmentConfigured && !uvFallback) {
                            UiState.WaitingForUvEntry(
                                (_uiState.value as? UiState.WaitingForUvEntry)?.error
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

                        val errorState = when (error) {
                            is PinRequiredClientError -> Error.PinRequiredError
                            is PinInvalidClientError -> Error.IncorrectPinError(error.pinRetries)
                            is UvInvalidClientError -> Error.IncorrectUvError(error.retries)
                            is ClientError -> {
                                when (error.errorCode) {
                                    ClientError.Code.CONFIGURATION_UNSUPPORTED -> when ((error.cause as? CtapException)?.ctapError) {
                                        CtapException.ERR_KEY_STORE_FULL -> Error.OperationError(
                                            error.cause
                                        )

                                        else -> Error.DeviceNotConfiguredError
                                    }

                                    else ->
                                        when ((error.cause as? CtapException)?.ctapError) {
                                            CtapException.ERR_PIN_BLOCKED -> Error.PinBlockedError
                                            CtapException.ERR_PIN_AUTH_BLOCKED -> Error.PinAuthBlockedError
                                            CtapException.ERR_PIN_INVALID -> Error.IncorrectPinError(
                                                null
                                            )

                                            CtapException.ERR_PIN_NOT_SET -> Error.PinNotSetError
                                            CtapException.ERR_PIN_POLICY_VIOLATION -> Error.IncorrectPinError(
                                                null
                                            )

                                            CtapException.ERR_UV_BLOCKED,
                                            CtapException.ERR_PUAT_REQUIRED -> Error.UvBlockedError

                                            else -> Error.OperationError(error.cause)
                                        }
                                }
                            }

                            else -> Error.UnknownError(error.message)
                        }
                        _uiState.value = when (errorState) {
                            is Error.PinRequiredError,
                            is Error.PinBlockedError,
                            is Error.PinAuthBlockedError,
                            is Error.IncorrectPinError -> UiState.WaitingForPinEntry(
                                errorState,
                                lastEnteredPin
                            )

                            is Error.UvBlockedError -> {
                                uvFallback = true
                                UiState.WaitingForPinEntry(
                                    errorState,
                                    lastEnteredPin
                                )
                            }

                            is Error.IncorrectUvError -> UiState.WaitingForUvEntry(errorState)
                            is Error.PinNotSetError -> UiState.PinNotSetError()
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
    fun onEnterPin(pin: String) {
        lastEnteredPin = pin
        pinValue = pin.ifEmpty { null }
        signalRetry(forUsb = uvFallback)
    }

    // executed after the user taps the "Create PIN" button
    fun onCreatePin(pin: String) {
        newPinValue = pin.ifEmpty { null }
        // we don't setup USB because there is no
        // need for touch. The touch will be required after onPinCreatedConfirmation
        signalRetry(forUsb = false)
    }

    // executed after the user taps the "Continue" button in PIN created screen
    fun onPinCreatedConfirmation() {
        signalRetry()
    }

    // executed after the user taps the "Retry" button in Error screen
    fun onErrorConfirmation() {
        lastEnteredPin = ""
        pinValue = null
        uvFallback = false
        signalRetry()
    }

    // job for changing the uiState with delay
    // used currently for setting TouchKey state when USB key is connected
    // default delay is value which worked best
    private var uiStateTimerJob: Job? = null
    fun setUiStateWithDelay(newState: UiState, delayMillis: Long = 500) {
        uiStateTimerJob?.cancel()
        uiStateTimerJob = viewModelScope.launch {
            delay(delayMillis)
            _uiState.value = newState
        }
    }

    fun cancelUiStateTimer() {
        uiStateTimerJob?.cancel()
        uiStateTimerJob = null
    }
}
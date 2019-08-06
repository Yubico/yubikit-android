/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.demo.fido

import android.app.Activity
import android.content.Intent
import android.content.IntentSender
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.yubico.yubikit.demo.fido.arch.ErrorLiveEvent
import com.yubico.yubikit.demo.fido.arch.SingleLiveEvent
import com.yubico.yubikit.demo.fido.settings.Ramps
import com.yubico.yubikit.fido.*
import com.yubico.yubikit.fido.exceptions.FidoException
import com.yubico.yubikit.utils.Callback
import com.yubico.yubikit.utils.OperationCanceledException


/**
 * View model that represents communication with secure hardware for FIDO2
 * Uses Fido API [com.google.android.gms.fido.fido2.Fido2ApiClient]
 * Diagram how FIDO2/WebAuthN works: https://developers.yubico.com/FIDO2/
 */
private const val TAG = "Fido2ViewModel"
class Fido2ViewModel(private val clientApi: Fido2ClientApi) : ViewModel() {

    private val _error = ErrorLiveEvent(TAG)
    private val _pendingIntentReady = SingleLiveEvent<Int>()
    private val _makeCredentialResponse = SingleLiveEvent<MakeCredentialResponse>()
    private val _getAssertionResponse = SingleLiveEvent<GetAssertionResponse>()

    /**
     * This data needs to be observed in order to send it to server to finish authentication process
     * @return results of key assertion/authentication process on authenticator
     */
    val assertionResponse: LiveData<GetAssertionResponse> = _getAssertionResponse

    /**
     * Live data of error occurred during usage of authenticator, needs to be observed to propagate error to user
     * @return error as throwable that should always have message, in case of cancellation returns OperationCanceledException
     */
    val error: LiveData<Throwable> = _error

    /**
     * Live data of readiness to open activity that communicates with authenticator
     * Observe it in order to launch that activity
     * This is SingleLiveEvent, must have only 1 active observer at a time
     * @return 2 possible values: MAKE_CREDENTIAL_REQUEST_CODE or GET_ASSERTION_REQUEST_CODE
     */
    val requestCode: LiveData<Int>
        get() = _pendingIntentReady

    /**
     * This data needs to be observed in order to send it to server to finish registration process
     * @return results of key registration process on authenticator
     */
    val makeCredentialResponse: LiveData<MakeCredentialResponse>
        get() = _makeCredentialResponse

    /**
     *
     * Registration Ceremony
     * The ceremony where a user, a Relying Party, and the user’s client (containing at least one authenticator)
     * work in concert to create a public key credential and associate it with the user’s Relying Party account.
     * Note that this includes employing a test of user presence or user verification.
     *
     * Invoke when you start registration process with data received from backend during registration_begin request
     * @param options data received from backend
     */
    fun registerKey(options: MakeCredentialOptions) {
        if (Ramps.isEmulator()) {
            _error.value = UnsupportedOperationException("Fido API doesn't work on emulator")
            return
        }
        clientApi.registerKey(options, object : Callback {
            override fun onSuccess() {
                _pendingIntentReady.value = REGISTER_KEY
            }

            override fun onError(throwable: Throwable) {
                _error.value = throwable
            }
        })
    }

    /**
     * Launch User Verification Activity
     * where authenticator locally authorizes the invocation of the authenticatorMakeCredential and authenticatorGetAssertion operations.
     * User verification MAY be instigated through various authorization gesture modalities;
     * for example, through a touch plus pin code, password entry, or biometric recognition (e.g., presenting a fingerprint) [ISOBiometricVocabulary].
     *
     * Invoke that when pending intent prepared and requestCode set to value
     * @param parent activity that used to launch pending intent, it's going to stay on back stack when Authenticator activity is visible
     */
    fun launch(parent: Activity) {
        try {
            clientApi.launch(parent)
        } catch (e: IntentSender.SendIntentException) {
            _error.value = e
        }

    }

    /**
     * Invoke when you start assertion/authentication process with data received from backend during authentication_begin request
     * @param options data received from backend
     */
    fun authenticateWithKey(options: GetAssertionOptions) {
        if (Ramps.isEmulator()) {
            _error.value = UnsupportedOperationException("Fido API doesn't work on emulator")
            return
        }
        clientApi.authenticateWithKey(options, object : Callback {
            override fun onSuccess() {
                _pendingIntentReady.value = AUTHENTICATE_WITH_KEY
            }

            override fun onError(throwable: Throwable) {
                _error.value = throwable
            }
        })
    }

    /**
     * Invoke when activity that you provided in launch method will get onActivityResult invoked
     * Pass all params that you've got with onActivityResult call
     * @param requestCode only {@value MAKE_CREDENTIAL_REQUEST_CODE} and {@value GET_ASSERTION_REQUEST_CODE} will be handled
     * @param resultCode RESULT_OK in case of success, RESULT_CANCELED when operation was cancelled, otherwise error
     * @param data contains serialized data of response or error
     */
    fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        Log.d(TAG, "onActivityResult requestCode:$requestCode resultCode:$resultCode")
        try {
            val response = clientApi.getAuthenticatorResponse(requestCode, resultCode, data)
            if (response is MakeCredentialResponse) {
                _makeCredentialResponse.value = response
            } else if (response is GetAssertionResponse) {
                _getAssertionResponse.value = response
            }
        } catch (e: FidoException) {
            _error.value = e
        } catch (e: OperationCanceledException) {
            _error.value = e
        }
    }

    companion object {
        const val REGISTER_KEY = 1
        const val AUTHENTICATE_WITH_KEY = 2
    }
    /**
     * A creator is used to inject the application object into the ViewModel
     */
    @Suppress("UNCHECKED_CAST")
    class Factory(private val fido2ClientApi: Fido2ClientApi) : ViewModelProvider.NewInstanceFactory() {

        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return Fido2ViewModel(fido2ClientApi) as T
        }
    }
}


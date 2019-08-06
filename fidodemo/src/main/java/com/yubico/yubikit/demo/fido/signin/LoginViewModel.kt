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

package com.yubico.yubikit.demo.fido.signin

import android.util.Base64
import android.util.Log
import androidx.lifecycle.*
import com.yubico.yubikit.demo.fido.arch.ErrorLiveEvent
import com.yubico.yubikit.demo.fido.arch.SingleLiveEvent
import com.yubico.yubikit.demo.fido.communication.*
import com.yubico.yubikit.demo.fido.network.DataException
import com.yubico.yubikit.demo.fido.network.ResourceNotFoundException
import com.yubico.yubikit.demo.fido.network.ServiceCallback
import com.yubico.yubikit.demo.fido.settings.BuildConfig
import com.yubico.yubikit.demo.fido.settings.Ramps
import com.yubico.yubikit.fido.AuthenticatorAttachment
import com.yubico.yubikit.fido.GetAssertionOptions
import com.yubico.yubikit.fido.MakeCredentialOptions
import com.yubico.yubikit.fido.RelyingParty
import retrofit2.Call
import retrofit2.Response

/**
 * View model for sign in process
 */
private const val TAG = "LoginViewModel"
class LoginViewModel(private val networkService: NetworkApi, private val accountStorage: AccountStorage) : ViewModel() {

    // account data from network that requires 2nd factor auth
    private var unauthenticatedUser: User? = null
    private var authRequestId: String? = null

    // account data from Account Storage
    private val _user = UserData(accountStorage)

    // account data from network + account storage (fully authenticated user)
    private val _signedUser = MediatorLiveData<User>().apply {
        addSource(_user) { value ->
            setValue(value)
            value?.let {
                accountStorage.saveAccount(value)
                _error.value = null
            }
        }
    }
    val signedUser : LiveData<User> by lazy {
        _signedUser
    }

    // option from network required for FIDO 2nd factor auth
    private val _getAssertionOptions : SingleLiveEvent<GetAssertionOptions> by lazy {
        SingleLiveEvent<GetAssertionOptions>()
    }
    val getAssertionOptions : LiveData<GetAssertionOptions> by lazy {
        _getAssertionOptions
    }

    // options to register key with FIDO for 2nd factor auth
    private val _makeCredentialOptions = SingleLiveEvent<MakeCredentialOptions>()
    val makeCredentialOptions : LiveData<MakeCredentialOptions> = _makeCredentialOptions


    // passwordless accounts
    val passwordlessAccount
        get() = accountStorage.getPasswordLessAccount()

    val usedAccounts
        get() = accountStorage.readHistory()

    // error that occurs during sign in
    private val _error = ErrorLiveEvent(TAG)
    val error: LiveData<Throwable> = _error

    fun attemptLogin(userName: String, password: String) {
        networkService.login(UserCreds(userName, password, BuildConfig.getNamespace())).enqueue(object : ServiceCallback<LoginStatus>() {
            override fun onFailure(call: Call<LoginStatus>, t: Throwable) {
                _error.value = t
            }

            override fun onResponse(call: Call<LoginStatus>, response: Response<LoginStatus>) {
                if (!handledErrorResponse(call, response)) {
                    // successfully logged in
                    val receivedUser = response.body()?.userData?.user
                    Log.d(TAG, "logged in user ${receivedUser?.username}")
                    processMultiFactorAuth(receivedUser)
                }
            }
        })
    }

    fun signUp(userName: String, password: String) {
        networkService.user(UserCreds(userName, password, BuildConfig.getNamespace())).enqueue(object : ServiceCallback<UserStatus>() {
            override fun onFailure(call: Call<UserStatus>, t: Throwable) {
                _error.value = t
            }

            override fun onResponse(call: Call<UserStatus>, response: Response<UserStatus>) {
                if (!handledErrorResponse(call, response)) {
                    val receivedUser = response.body()?.user
                    Log.d(TAG, "signed up user ${receivedUser?.username}")
                    processMultiFactorAuth(receivedUser);
                }
            }
        })
    }

    fun authenticateBegin(user: User, passwordLess: Boolean = false) {
        if (passwordLess) {
            unauthenticatedUser = user

        }
        networkService.authenticateBegin(AuthBeginRequest(if (!passwordLess) user.uuid else null, BuildConfig.getNamespace())).enqueue(object : ServiceCallback<AuthBeginResponse>() {
            override fun onFailure(call: Call<AuthBeginResponse>, t: Throwable) {
                _error.value = t
            }

            override fun onResponse(call: Call<AuthBeginResponse>, response: Response<AuthBeginResponse>) {
                if (!handledErrorResponse(call, response)) {
                    response.body()?.let {
                        val data = it.data
                        val key = data.publicKey

                        // in real passwordless FIDO2 experience we should pass no allowedCredentials and get non-null userHandle with resident credential
                        // but FIDO2 API doesn't allow to have empty or null allowCredentials list yet
                        var allowedCredentials = if (passwordLess) arrayListOf(accountStorage.readCredentialId(user) ?: ByteArray(0))
                                                 else key.allowCredentials.map { credential -> Base64.decode(credential.id, Base64.DEFAULT) }
                        authRequestId = data.requestId
                        _getAssertionOptions.value = GetAssertionOptions(
                                key.rpId,
                                Base64.decode(key.challenge, Base64.DEFAULT),
                                allowedCredentials )
                            .timeoutMs(key.timeout)
                        Log.d(TAG, "authenticateBegin for  ${data.requestId}")
                    }
                }
            }
        })
    }

    fun authenticateFinish(
        credentialId: ByteArray,
        authenticatorData: ByteArray,
        clientDataJSON: ByteArray,
        signature: ByteArray,
        userHandle: ByteArray?) {
        check(authRequestId != null) {"authenticateFinish invoked w/o calling authenticateBegin"}
        check(unauthenticatedUser != null) {"authenticateFinish invoked w/o calling authenticateBegin"}
        networkService.authenticateFinish(AuthFinishRequest(
                authRequestId!!,
                Assertion(credentialId, authenticatorData, clientDataJSON, signature, userHandle),
                unauthenticatedUser!!.uuid, BuildConfig.getNamespace())).enqueue(object : ServiceCallback<AuthFinishResponse>() {
            override fun onFailure(call: Call<AuthFinishResponse>, t: Throwable) {
                _error.value = t
                // if this request got resource not found response it means user was deleted on server we should forget that user
                if (t is ResourceNotFoundException) {
                    accountStorage.removePasswordLessAccount(unauthenticatedUser!!)
                }
            }

            override fun onResponse(call: Call<AuthFinishResponse>, response: Response<AuthFinishResponse>) {
                if (!handledErrorResponse(call, response)) {
                    val receivedData = response.body()?.data
                    val receivedUser = receivedData?.user
                    if (receivedData?.authenticatorAttachment != null && receivedUser != null) {
                        if (receivedData.authenticatorAttachment == AuthenticatorAttachment.PLATFORM.toString()) {
                            // account was logged in using platform authenticator, it means he has ability to sign in with it only
                            accountStorage.savePasswordLessAccount(receivedUser, credentialId, receivedData.deviceId)
                        } else {
                            // account was logged in using cross platform authenticator, it means he doesn't have platform one
                            accountStorage.removePasswordLessAccount(receivedUser)
                        }
                    }
                    if (receivedUser?.uuid?.equals(unauthenticatedUser?.uuid) == true)
                        _user.value = unauthenticatedUser
                    Log.d(TAG, "authenticateFinish : logged in user ${receivedUser?.username}")

                }
            }
        })
    }


    fun registerBegin(userData: User) {
        networkService.registerBegin(userData.uuid, RegisterBeginRequest(AuthenticatorAttachment.CROSS_PLATFORM.toString())).enqueue(object : ServiceCallback<RegisterBeginResponse>() {
            override fun onFailure(call: Call<RegisterBeginResponse>, t: Throwable) {
                Log.e(TAG, "registerBegin failed: ${t.message}", t)
                _error.value = t
            }

            override fun onResponse(call: Call<RegisterBeginResponse>, response: Response<RegisterBeginResponse>) {
                if (!handledErrorResponse(call, response)) {
                    response.body()?.let {
                        val data = it.data
                        val key = data.publicKey
                        val rp = RelyingParty(key.rp.id, key.rp.name);
                        val user = com.yubico.yubikit.fido.User(key.user.id, key.user.username, key.user.displayName)
                        try {
                            authRequestId = data.requestId
                            _makeCredentialOptions.value = MakeCredentialOptions(rp, user, key.challenge)
                                    .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
                                    .attestation(key.attestation)
                                    .excludeCredentials(key.excludeCredentials.map { cred -> cred.id })
                                    .algorithms(key.pubKeyCredParams.map { pubKeyCredParam -> pubKeyCredParam.alg })
                                    .timeoutMs(key.timeout)
                        } catch (e : Exception) {
                            _error.value = e
                        }
                        Log.d(TAG, "registerBegin for  ${data.requestId}")
                    }
                }
            }

        })
    }

    fun registerFinish(credentialId: ByteArray, attestation: ByteArray, clientDataJSON:ByteArray) {
        check(authRequestId != null) {"registerFinish invoked w/o calling registerBegin"}
        check(unauthenticatedUser != null) {"registerFinish invoked w/o calling registerBegin"}

        Log.d(TAG, "registering credential: " + Base64.encodeToString(credentialId, Base64.DEFAULT))
        val request = RegisterFinishRequest(authRequestId!!, Attestation(attestation, clientDataJSON))
        networkService.registerFinish(unauthenticatedUser!!.uuid, request).enqueue(object : ServiceCallback<RegisterFinishResponse>() {
            override fun onFailure(call: Call<RegisterFinishResponse>, t: Throwable) {
                Log.e(TAG, "registerFinish failed: ${t.message}", t)
                _error.value = t
            }

            override fun onResponse(call: Call<RegisterFinishResponse>, response: Response<RegisterFinishResponse>) {
                if (!handledErrorResponse(call, response)) {
                    Log.d(TAG, "registerFinish for  $authRequestId")
                    _signedUser.value = unauthenticatedUser
                }
            }

        })
    }

    fun logout(userData: User) {
        networkService.logout(userData.uuid).enqueue(object : ServiceCallback<OperationStatus>() {
            override fun onFailure(call: Call<OperationStatus>, t: Throwable) {
                Log.e(TAG, "log out failed: ${t.message}", t)
                _error.value = t
                if (t is DataException) {
                    _signedUser.value = null
                    // if we've got server error on logout it means our account got expired
                    // let's sign out user locally so that he can sign in again
                    CookieStorage.invalidateCookies()
                }
            }

            override fun onResponse(call: Call<OperationStatus>, response: Response<OperationStatus>) {
                if (!handledErrorResponse(call, response)) {
                    Log.d(TAG, "logged out user ${userData.uuid}")
                    _signedUser.value = null
                    // successfully logged out, nuke Cookies
                    CookieStorage.invalidateCookies()
                }
            }
        })
    }

    /**
     * Handle cases if sing in/sign up requires 2nd factor authentication
     */
    private fun processMultiFactorAuth(receivedUser: User?) {
        if (receivedUser == null) {
            _error.value = DataException("User data is not received")
        } else {
            unauthenticatedUser = receivedUser
            if (receivedUser.authenticators?.isEmpty() == false) {
                // requires 2nd factor auth
                authenticateBegin(receivedUser)
            } else {
                if (Ramps.PASSWORDLESS_EXPERIENCE.getValue(null) == true) {
                    registerBegin(receivedUser)
                } else {
                    _user.value = receivedUser
                }
            }
        }
    }

    class UserData(private val accountStorage : AccountStorage) : MutableLiveData<User>() {
        init {
            if (CookieStorage.hasCookies()) {
                value = accountStorage.getAccount()
            } else {
                value = null
            }
        }

        override fun onActive() {
            super.onActive()
            CookieStorage.registerListener(object : CookieStorage.CookiesChangeListener {
                override fun onRemoved(userRemoved: Boolean) {
                    accountStorage.removeAccount()
                    // if user was removed from server we can't sign him passwordless
                    if (userRemoved) {
                        value?.let {
                            accountStorage.removePasswordLessAccount(it)
                        }
                    }
                    postValue(null)
                }
            })
        }

        override fun onInactive() {
            CookieStorage.unregisterListener()
            super.onInactive()
        }
    }

    /**
     * A creator is used to inject the application object into the ViewModel
     */
    class Factory(private val networkApi: NetworkApi, private val accountStorage: AccountStorage) : ViewModelProvider.NewInstanceFactory() {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return LoginViewModel(networkApi, accountStorage) as T
        }
    }
}
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

package com.yubico.yubikit.demo.fido.listview

import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.lifecycle.*

import com.yubico.yubikit.demo.fido.arch.ErrorLiveEvent
import com.yubico.yubikit.demo.fido.arch.SingleLiveEvent
import com.yubico.yubikit.demo.fido.communication.*
import com.yubico.yubikit.demo.fido.db.Authenticator
import com.yubico.yubikit.demo.fido.db.LocalCache
import com.yubico.yubikit.demo.fido.network.DataException
import com.yubico.yubikit.demo.fido.network.ResourceNotFoundException
import com.yubico.yubikit.demo.fido.network.ServiceCallback
import com.yubico.yubikit.demo.fido.settings.BuildConfig
import com.yubico.yubikit.demo.fido.settings.Ramps
import com.yubico.yubikit.demo.fido.signin.AccountStorage
import com.yubico.yubikit.demo.fido.signin.CookieStorage
import com.yubico.yubikit.fido.AuthenticatorAttachment
import com.yubico.yubikit.fido.GetAssertionOptions
import com.yubico.yubikit.fido.MakeCredentialOptions
import com.yubico.yubikit.fido.RelyingParty
import retrofit2.Call
import retrofit2.Response
import java.lang.Exception
import java.lang.IllegalStateException
import java.util.concurrent.ConcurrentLinkedQueue

private const val OPERATION_ID = "operationId"
private const val AUTHENTICATOR_ID = "authenticatorId"
private const val DELETE_OPERATION_ID = 1

/**
 * View model that contains all network requests to webauthn server to operate with authenticators (add, rename, delete)
 */
class AuthenticatorModel(private val networkService: NetworkApi, private val localCache: LocalCache, private val accountStorage: AccountStorage, val userData : User) : ViewModel() {
    private val TAG = "AuthenticatorModel"

    // request identification to coordinate begin and finish network calls
    private var registerRequest : Request? = null
    private var authRequest : Request? = null
    private val authRequestQueue = ConcurrentLinkedQueue<Bundle>()

    // avoid triggering multiple requests in the same time
    private val _requestInProgress = MutableLiveData<Boolean>().apply {
        value = false
    }
    val networkRequestInProgress : LiveData<Boolean> = _requestInProgress

    // list of authenticators that gets populated from DB
    val authenticators: LiveData<List<AuthenticatorItem>> by lazy {
        loadAuthenticators()
        Transformations.map(localCache.authenticatorByUser(userData.uuid), ::createAuthenticatorItem)
    }

    // options to register key with FIDO for 2nd factor auth
    private val _makeCredentialOptions = SingleLiveEvent<MakeCredentialOptions>()
    val makeCredentialOptions : LiveData<MakeCredentialOptions> = _makeCredentialOptions

    private val _getAssertionOptions by lazy {
        SingleLiveEvent<GetAssertionOptions>()
    }
    val getAssertionOptions : LiveData<GetAssertionOptions> by lazy {
        _getAssertionOptions
    }

    private val _authRequestResult  by lazy {
        SingleLiveEvent<RequestResult>()
    }
    val authResultRequest : LiveData<RequestResult> by lazy {
        _authRequestResult
    }

    private val _error = ErrorLiveEvent(TAG)
    val error : LiveData<Throwable> = _error

    /**
     * Loads authenticators from local cache and from server and notifies {@link AuthenticatorModel::authenticators} about changes in loaded data
     */
    fun loadAuthenticators() {
        if (_requestInProgress.value == true) {
            return
        }
        _requestInProgress.value = true
        networkService.authenticator(userData.uuid).enqueue(object : ServiceCallback<AuthenticatorStatus>() {
            override fun onFailure(call: Call<AuthenticatorStatus>, t: Throwable) {
                Log.e(TAG, "load authenticator failed: ${t.message}", t)
                _error.value = t

                // if this request got resource not found response it means user was deleted on server
                if (t is ResourceNotFoundException) {
                    CookieStorage.invalidateCookies(true)
                }
                _requestInProgress.value = false
            }

            override fun onResponse(call: Call<AuthenticatorStatus>, response: Response<AuthenticatorStatus>) {
                if (!handledErrorResponse(call, response)) {
                    val networkAuthenticators = response.body()?.authenticatorData?.authenticators?.webauthn ?: emptyList()
                    Log.d(TAG, "received ${networkAuthenticators.size} of authenticators")

                    // save list of authenticators from network to local cache, this will trigger update on live data
                    localCache.insert(networkAuthenticators, userData.uuid) {
                        // if list authenticators is empty than db change doesn't happen and livedata.onchange won't be triggered
                        // let's make sure that UI gets notified to stop progress bar/spinner
                        _requestInProgress.postValue(false)
                    }

                    if (Ramps.PASSWORDLESS_EXPERIENCE.getValue(null) == true) {
                        val localDeviceId = accountStorage.getDeviceId()
                        when {
                            networkAuthenticators.none { item -> item.metadata.authenticatorAttachment == AuthenticatorAttachment.CROSS_PLATFORM.toString() } -> // user removed all keys
                                _error.value = NoCrossPlatAuthenticatorException("Register at least 1 authenticator")
                            networkAuthenticators.none { item -> item.id == localDeviceId } -> {
                                _error.value = NoPlatformAuthenticatorException("Register platform authenticator")
                                // if platform authenticator was removed from backend we need to make sure to remove it from client password less experience
                                accountStorage.removePasswordLessAccount(userData)
                            }
                        }
                    }
                }
            }

        })
    }

    /**
     * Starts registration process for particular type of authentication (platform or crossplatform)
     */
    fun registerBegin(authenticatorAttachment: AuthenticatorAttachment) {
        networkService.registerBegin(userData.uuid, RegisterBeginRequest(authenticatorAttachment.toString())).enqueue(object : ServiceCallback<RegisterBeginResponse>() {
            override fun onFailure(call: Call<RegisterBeginResponse>, t: Throwable) {
                Log.e(TAG, "registerBegin failed: ${t.message}", t)
                _error.value = t
            }

            override fun onResponse(call: Call<RegisterBeginResponse>, response: Response<RegisterBeginResponse>) {
                if (!handledErrorResponse(call, response)) {
                    response.body()?.let {
                        val data = it.data
                        val key = data.publicKey
                        val rp = RelyingParty(key.rp.id, key.rp.name)
                        val user = com.yubico.yubikit.fido.User(key.user.id, key.user.username, key.user.displayName)
                        try {
                            registerRequest = Request(data.requestId, authenticatorAttachment)
                            _makeCredentialOptions.value = MakeCredentialOptions(rp, user, key.challenge)
                                    .authenticatorAttachment(authenticatorAttachment)
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

    /**
     * Finishes registration process and adds authenticator on server
     */
    fun registerFinish(credentialId: ByteArray, attestation: ByteArray, clientDataJSON:ByteArray) {
        registerRequest?.let {
            Log.d(AuthenticatorListFragment.TAG, "registering credential: " + Base64.encodeToString(credentialId, Base64.DEFAULT))
            val request = RegisterFinishRequest(it.id, Attestation(attestation, clientDataJSON))
            networkService.registerFinish(userData.uuid, request).enqueue(object : ServiceCallback<RegisterFinishResponse>() {
                override fun onFailure(call: Call<RegisterFinishResponse>, t: Throwable) {
                    Log.e(TAG, "registerFinish failed: ${t.message}", t)
                    _error.value = t
                }

                override fun onResponse(call: Call<RegisterFinishResponse>, response: Response<RegisterFinishResponse>) {
                    if (!handledErrorResponse(call, response)) {
                        Log.d(TAG, "registerFinish for  ${it.id}")

                        val deviceId = response.body()?.data?.deviceId
                        // store password less accounts to use it for next login
                        if (it.authenticatorAttachment == AuthenticatorAttachment.PLATFORM) {
                            accountStorage.savePasswordLessAccount(userData, credentialId, deviceId)
                        }

                        // successfully added new key, refresh data from backend
                        loadAuthenticators()
                    }
                }

            })
        } ?: run {
            throw IllegalStateException("registerFinish invoked w/o calling registerBegin")
        }
    }

    /**
     * Start authentication process for particular type of authentication (platform or crossplatform)
     */
    fun authenticateBegin(authenticatorAttachment: AuthenticatorAttachment) {
        networkService.authenticateBegin(AuthBeginRequest(userData.uuid, BuildConfig.getNamespace(), authenticatorAttachment == AuthenticatorAttachment.CROSS_PLATFORM)).enqueue(object : ServiceCallback<AuthBeginResponse>() {
            override fun onFailure(call: Call<AuthBeginResponse>, t: Throwable) {
                _authRequestResult.value = RequestResult.Error(t)
            }

            override fun onResponse(call: Call<AuthBeginResponse>, response: Response<AuthBeginResponse>) {
                if (!handledErrorResponse(call, response)) {
                    response.body()?.let {
                        val data = it.data
                        val key = data.publicKey

                        val allowedCredentials = key.allowCredentials.map { credential -> Base64.decode(credential.id, Base64.DEFAULT) }

                            // if we've got passwordless experience we don't allow to authenticate operations without step up/platform authenticator
                        var residentCredential =  Base64.encodeToString(accountStorage.readCredentialId(userData) ?: ByteArray(0), Base64.DEFAULT)
                        if (Ramps.PASSWORDLESS_EXPERIENCE.getValue(null) == true
                            && authenticatorAttachment == AuthenticatorAttachment.PLATFORM
                            && !allowedCredentials.map { credential -> Base64.encodeToString(credential, Base64.DEFAULT)}.contains(residentCredential)) {
                            // if device or backend is not aware of platform authenticator we shouldn't allow to authenticate/use passwordless expirience
                            _error.value = NoPlatformAuthenticatorException("Operation is not allowed without platform authenticator")
                            accountStorage.removePasswordLessAccount(userData)
                        } else {
                            authRequest = Request(data.requestId, authenticatorAttachment)
                            _getAssertionOptions.value = GetAssertionOptions(
                                key.rpId,
                                Base64.decode(key.challenge, Base64.DEFAULT),
                                allowedCredentials
                            ).timeoutMs(key.timeout)
                            Log.d(TAG, "authenticateBegin for  ${data.requestId}")
                        }
                    }
                }
            }
        })
    }

    /**
     * Finishes authentication process that notifies authRequetResult
     */
    fun authenticateFinish(
            credentialId: ByteArray,
            authenticatorData: ByteArray,
            clientDataJSON: ByteArray,
            signature: ByteArray,
            userHandle: ByteArray?) {
        check(authRequest != null) {"authenticateFinish invoked w/o calling authenticateBegin"}
        networkService.authenticateFinish(AuthFinishRequest(
                authRequest!!.id,
                Assertion(credentialId, authenticatorData, clientDataJSON, signature, userHandle),
                userData.uuid, BuildConfig.getNamespace())).enqueue(object : ServiceCallback<AuthFinishResponse>() {
            override fun onFailure(call: Call<AuthFinishResponse>, t: Throwable) {
                _authRequestResult.value = RequestResult.Error(t)
            }

            override fun onResponse(call: Call<AuthFinishResponse>, response: Response<AuthFinishResponse>) {
                if (!handledErrorResponse(call, response)) {
                    val receivedData = response.body()?.data
                    if (receivedData != null) {
                        _authRequestResult.value = RequestResult.Success(receivedData)
                    } else {
                        _authRequestResult.value = RequestResult.Error(DataException("Not received authentication finish results"))
                    }
                }
            }
        })
    }

    /**
     * Rename authenticator on server
     */
    fun rename(deviceId: String, newName: String) {
        networkService.rename(userData.uuid, deviceId, RenameProperty(newName)).enqueue(object  : ServiceCallback<OperationStatus>() {
            override fun onFailure(call: Call<OperationStatus>, t: Throwable) {
                _error.value = t
            }

            override fun onResponse(call: Call<OperationStatus>, response: Response<OperationStatus>) {
                if (!handledErrorResponse(call, response)) {
                    Log.d(TAG, "renamed key $deviceId")
                    // successfully renamed key, refresh data from backend
                    loadAuthenticators()
                }
            }
        })
    }

    /**
     * Delete authenticator from server
     */
    fun delete(authenticator: AuthenticatorItem, validate: Boolean) {
        if (validate && BuildConfig.isWebAuthNNameSpace() &&
                authenticator.authenticatorAttachment == AuthenticatorAttachment.CROSS_PLATFORM &&
                authenticators.value?.filter { item -> item.authenticatorAttachment == AuthenticatorAttachment.CROSS_PLATFORM }?.size == 1) {
            // do not allow to remove last cross-platform authenticator if passwordless experience
            // webauthn namespace doesn't validates it on backend
            _error.value = IllegalStateException("At least 1 cross-platform authenticator required")
            return
        }

        if (validate && authenticator.id == accountStorage.getDeviceId()) {
            // The revocation is a security sensitive operation
            // so it requires an additional verification step to make sure that only the owner can revoke
            // and not someone else who stole the phone
            var operation = Bundle().apply {
                putInt(OPERATION_ID, DELETE_OPERATION_ID)
                putParcelable(AUTHENTICATOR_ID, authenticator)
            }
            authRequestQueue.add(operation)
            authenticateBegin(AuthenticatorAttachment.PLATFORM)
            return
        }

        networkService.delete(userData.uuid, authenticator.id).enqueue(object  : ServiceCallback<OperationStatus>() {
            override fun onFailure(call: Call<OperationStatus>, t: Throwable) {
                _error.value = t
            }

            override fun onResponse(call: Call<OperationStatus>, response: Response<OperationStatus>) {
                if (!handledErrorResponse(call, response)) {
                    Log.d(TAG, "removed key ${authenticator.id}")


                    if (authenticator.id == accountStorage.getDeviceId()) {
                        // remove passwordless account because we revoke device/platform authenticator
                        accountStorage.removePasswordLessAccount(userData)
                    }

                    // successfully removed key, refresh data from backend
                    loadAuthenticators()
                }
            }
        })
    }

    /**
     * Invoke when authentication process got successful response (has queue of operations that requested authentication)
     */
    fun confirmOperation() {
        // get operation from queue that requires approval
        val operation = authRequestQueue.remove()
        if (operation != null) {
            when(operation.getInt(OPERATION_ID)) {
                DELETE_OPERATION_ID -> delete(operation.getParcelable(AUTHENTICATOR_ID)!!, false)
            }
        }
    }

    private fun createAuthenticatorItem(data: List<Authenticator>): List<AuthenticatorItem> {
        return data.map {
            item ->
            var attachment =
                    try {
                        AuthenticatorAttachment.fromString(item.attachment)
                    } catch (e : AuthenticatorAttachment.UnsupportedAttachmentException) {
                        Log.e(TAG, "Authenticator received with unsupported attachment", e)
                        null
                    }
            AuthenticatorItem(item.id, item.name, item.deviceType, item.lastUsed, item.registeredAt, item.type, attachment)
        }
    }

    private data class Request(val id: String, val authenticatorAttachment: AuthenticatorAttachment)

    sealed class RequestResult {
        data class Success(val auth: AuthFinishData) : RequestResult()
        data class Error(val error: Throwable) : RequestResult()
    }

    class Factory(private val networkApi: NetworkApi, private val localCache: LocalCache, private val accountStorage: AccountStorage, private val userData: User) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return AuthenticatorModel(networkApi, localCache, accountStorage, userData) as T
        }
    }
}
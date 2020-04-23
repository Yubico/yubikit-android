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

package com.yubico.yubikit.demo.oath

import android.net.Uri
import android.os.Bundle
import android.text.TextUtils
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.exceptions.ApduException
import com.yubico.yubikit.demo.YubikeyViewModel
import com.yubico.yubikit.demo.fido.arch.SingleLiveEvent
import com.yubico.yubikit.exceptions.BadRequestException
import com.yubico.yubikit.exceptions.YubiKeyCommunicationException
import com.yubico.yubikit.oath.*
import com.yubico.yubikit.transport.YubiKeySession
import com.yubico.yubikit.utils.Logger
import java.io.IOException
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors

const val SPECIAL_ISSUER_THAT_DOES_NOT_TRUNCATE_CODE = "Steam"
private const val OPERATION_ID = "operationId"
private const val CREDENTIAL = "credential"
private const val CREDENTIAL_DATA = "credentialData"
private const val PASSWORD = "password"
private const val FIVE_SECONDS = 5000.toLong()

/**
 * View model that handles oath operations for yubikit using yubikit manager for establishing connection and communication to device
 */
class OathViewModel(yubikitManager: YubiKitManager) : YubikeyViewModel(yubikitManager) {
    /**
     * For execution of communication with yubikey on background
     * Using single thread to avoid thread racing for different commands
     */
    private val executorService = Executors.newSingleThreadExecutor()

    /**
     * true if last select OATH returned challenge, which means that key requires password from user
     */
    var requireAuthentication: Boolean? = null

    /**
     * Map of credentials and codes received from keys (can be populated from multiple keys)
     */
    private val _credentials = MutableLiveData<Map<Credential, Code?>>()
    val credentials: LiveData<Map<Credential, Code?>> = _credentials

    /**
     * Event for successful password set operation
     */
    private val _passwordSet = SingleLiveEvent<Void>()
    val passwordSet: LiveData<Void> = _passwordSet

    /**
     * This is queue of requests that need to be executed on key
     * Helps to execute operations if they require authentication or yubikey to be plugged in or tapped over NFC
     */
    private val requestQueue = ConcurrentLinkedQueue<Bundle>()
    init {
        requestQueue.add(Bundle().apply { putSerializable(OPERATION_ID, Operations.CALCULATE_ALL) })
    }

    override fun YubiKeySession.executeDemoCommands() {
        // executes operations on background thread after connect() and atr and select() commands been sent
        executeOnBackgroundThread { oathApplication ->
            while (requestQueue.isNotEmpty()) {
                val validationRequest = requestQueue.filter {
                    Operations.VALIDATE == it.getSerializable(OPERATION_ID) as Operations
                }
                var request: Bundle?
                if (!validationRequest.isEmpty()) {
                    // if we need to authenticate we start with that operation
                    request = validationRequest.first()
                } else {
                    request = requestQueue.peek()
                }

                // empty bundle means no pending requests - nothing to execute
                request ?: return@executeOnBackgroundThread

                // execute operation from queue
                val pendingOperation = request.getSerializable(OPERATION_ID) as Operations
                try {
                    when (pendingOperation) {
                        Operations.VALIDATE -> {
                            val password = request.getString(PASSWORD)
                            Logger.d("Validate password for device ${oathApplication.applicationInfo.deviceId}")
                            if (!oathApplication.validate(password)) {
                                // if we couldn't validate password we remove all requests
                                // user will have to request new operation (refresh, add, remove credential, etc)
                                requestQueue.clear()
                                postError(WrongPasswordException("Password is incorrect"))
                            } else {
                                // NOTE: if validation succeeded we can store secret
                                // in KeyStore or in memory and reuse for next validations (depends on logic of application)
                                // OathApplication.calculateSecret() can be used to encrypt password
                                Logger.d("Authentication succeeded")
                            }
                        }
                        Operations.SET_CODE -> {
                            val password = request.getString(PASSWORD)
                            Logger.d("Set password for device ${oathApplication.applicationInfo.deviceId}")
                            oathApplication.setPassword(password)
                            requireAuthentication = !TextUtils.isEmpty(password)

                            // notify that password successfuly set
                            _passwordSet.postValue(null)
                            // NOTE: if new password was successfully set we can store secret
                            // in KeyStore or in memory and reuse for next validations (depends on logic of application)
                            // OathApplication.calculateSecret() can be used to encrypt password
                        }
                        Operations.ADD_CREDENTIAL -> {
                            val credentialData = request.getSerializable(CREDENTIAL_DATA) as CredentialData
                            Logger.d("Add credential = ${credentialData.id}")
                            if (oathApplication.listCredentials().map { it.id }.contains(credentialData.id)) {
                                throw BadRequestException("Credential for ${credentialData.id} already exists")
                            }
                            val credential = oathApplication.putCredential(credentialData)

                            val map = _credentials.value.orEmpty().toMutableMap()
                            if (credentialData.isTouchRequired) {
                                map[credential] = null
                            } else {
                                map[credential] = calculate(credential, oathApplication)
                            }
                            _credentials.postValue(map)
                        }
                        Operations.CALCULATE_ALL -> {
                            Logger.d("Retrieve all codes")
                            val receivedMap = oathApplication.calculateAll()
                            Logger.d("Received ${receivedMap.size} credentials from key")
                            val map = _credentials.value.orEmpty().toMutableMap()
                            for (credEntry in receivedMap.entries) {
                                val credential = credEntry.key
                                if (map[credential]?.isValid == true) {
                                    // skipping refresh of codes that still valid
                                    continue
                                }
                                if (credEntry.value == null) {
                                    // codes that returned null needs individual calculation
                                    // e.g. require touch (HOTP potentially can have require touch but it's not returned from YubiKey)
                                    if (SPECIAL_ISSUER_THAT_DOES_NOT_TRUNCATE_CODE == credential.issuer) {
                                        map[credential] = calculate(credential, oathApplication)
                                    } else {
                                        // note: these codes can be calculated using {@link OathViewModel#calculate()}
                                        // but if user didn't tap yubikey button all result won't be returned
                                        // so we give user to handle these items individually by hitting refresh operation
                                        map[credential] = null
                                    }
                                } else {
                                    // update recalculated values
                                    map[credential] = credEntry.value
                                }
                            }
                            _credentials.postValue(map)
                        }
                        Operations.CALCULATE -> {
                            val credential = request.getSerializable(CREDENTIAL) as Credential
                            val map = _credentials.value.orEmpty().toMutableMap()
                            map[credential] = calculate(credential, oathApplication)
                            _credentials.postValue(map)
                        }
                        Operations.REMOVE_CREDENTIAL -> {
                            val credential = request.getSerializable(CREDENTIAL) as Credential
                            Logger.d("Remove credential = ${credential.name}")
                            oathApplication.deleteCredential(credential.id)
                            val map = _credentials.value.orEmpty().toMutableMap()
                            map.remove(credential)
                            _credentials.postValue(map)
                        }
                        Operations.RESET -> {
                            Logger.d("Reset oath application for device ${oathApplication.applicationInfo.deviceId}")
                            // remove locally all credentials before reset, because after reset we won't be able to get list
                            val deviceCredentials = oathApplication.listCredentials()
                            val map = _credentials.value.orEmpty().toMutableMap()
                            for (credential in deviceCredentials) {
                                map.remove(credential)
                            }
                            _credentials.postValue(map)
                            oathApplication.reset()
                        }
                    }
                } catch (e : ApduException) {
                    // if user required to input password notify user about error and stop executing requests
                    // and do not remove from queue as they will be executed after validation
                    if (oathApplication.applicationInfo.isAuthenticationRequired && e.statusCode == OathApplication.AUTHENTICATION_REQUIRED_ERROR.toInt()) {
                        postError(AuthRequiredException("Authentication is required for operations on that device"))
                        break
                    }
                    postError(e)
                } catch (e : YubiKeyCommunicationException) {
                    postError(e)
                } catch (e : IOException) {
                    postError(e)
                }
                // removing successfully completed or failed request from queue
                requestQueue.remove(request)
            }
        }
    }

    private fun YubiKeySession.executeOnBackgroundThread(runCommand: (oathApplication: OathApplication) -> Unit) {
        executorService.execute {
            if (requestQueue.isEmpty()) {
                // if we've got no pending requests, refresh codes by default
                requestQueue.add(Bundle().apply { putSerializable(OPERATION_ID, Operations.CALCULATE_ALL) })
            }

            try {
                // send atr and select OATH application
                Logger.d("Select OATH application")
                OathApplication(this).use {
                    // run provided command/operation (put/calculate/delete/etc)
                    requireAuthentication = it.applicationInfo.isAuthenticationRequired
                    runCommand(it)
                }
            } catch (e: IOException) {
                postError(e)
            } catch (e: YubiKeyCommunicationException) {
                postError(e)
            }
        }
    }

    fun refreshList() {
        val refreshOp = Bundle().apply { putSerializable(OPERATION_ID, Operations.CALCULATE_ALL) }
        if (!requestQueue.contains(refreshOp)) {
            requestQueue.add(refreshOp)
            executeDemoCommands()
        }
    }

    fun refreshCredential(credential: Credential) {
        val refreshOp = Bundle().apply {
            putSerializable(OPERATION_ID, Operations.CALCULATE)
            putSerializable(CREDENTIAL, credential)
        }

        if (!requestQueue.contains(refreshOp)) {
            requestQueue.add(refreshOp)
            executeDemoCommands()
        }
    }

    fun addCredential(uri : Uri, isTouch: Boolean = false) {
        try {
            val credentialData = CredentialData.parseUri(uri)
            credentialData.isTouchRequired = isTouch
            requestQueue.add(Bundle().apply {
                putSerializable(OPERATION_ID, Operations.ADD_CREDENTIAL)
                putSerializable(CREDENTIAL_DATA, credentialData)
            })
            executeDemoCommands()
        } catch (e: ParseUriException) {
            postError(e)
        }
    }

    fun removeCredential(credential: Credential) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.REMOVE_CREDENTIAL)
            putSerializable(CREDENTIAL, credential)
        })
        executeDemoCommands()
    }

    fun checkPassword(password: String) {
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.VALIDATE)
            // NOTE: it's better to keep password encrypted in some permanent storage
            // and decrypt/extract when necessary
            // but for demo purpose we keep it unencrypted in memory until user run command
            // (in case of nfc we wait until user tap yubikey over reader)
            putSerializable(PASSWORD, password)
        })
        executeDemoCommands()
    }

    fun changePassword(oldPassword: String?, newPassword: String?) {
        // keep only 1 change password request in queue, only last one will be executed
        requestQueue.removeAll {
            val pendingOperation = it.getSerializable(OPERATION_ID) as Operations
            Operations.SET_CODE == pendingOperation || Operations.VALIDATE == pendingOperation
        }

        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.SET_CODE)
            putSerializable(PASSWORD, newPassword)
        })

        if (requireAuthentication == true && oldPassword != null) {
            checkPassword(oldPassword)
        } else {
            executeDemoCommands()
        }
    }

    /**
     * Calculates code for single credential
     */
    @Throws(IOException::class, ApduException::class)
    private fun calculate(credential: Credential, oathApplication: OathApplication) : Code {
        val map = _credentials.value.orEmpty().toMutableMap()
        val existingCode = map[credential]

        Logger.d("Get code for credential ${credential.id}")

        // recalculate code if it was never calculated or it's expired
        if (existingCode == null || !existingCode.isValid) {
            return oathApplication.calculate(credential)
        }

        // we can recalculate HOTP which are at least 5 seconds old
        if (credential.oathType == OathType.HOTP && existingCode.validFrom + FIVE_SECONDS > System.currentTimeMillis()) {
            return oathApplication.calculate(credential)
        }

        // we don't need to recalculate it in all other cases, keep existing one
        return existingCode
    }

    /**
     * Resets oath application (resets password and removes all credentials)
     */
    fun reset() {
        // if user is doing factory reset all previous requests can be dismissed
        requestQueue.clear()
        requestQueue.add(Bundle().apply {
            putSerializable(OPERATION_ID, Operations.RESET)
        })
        executeDemoCommands()
    }

    fun clearTasks() {
        requestQueue.clear()
    }

    enum class Operations {
        VALIDATE,
        SET_CODE,
        CALCULATE_ALL,
        CALCULATE,
        ADD_CREDENTIAL,
        REMOVE_CREDENTIAL,
        RESET
    }

    /**
     * Class factory to create instance of {@link OathViewModel}
     */
    class Factory(private val yubikitManager: YubiKitManager) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return OathViewModel(yubikitManager) as T
        }
    }
}
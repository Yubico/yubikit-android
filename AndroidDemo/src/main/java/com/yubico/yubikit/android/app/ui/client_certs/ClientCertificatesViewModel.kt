/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.android.app.ui.client_certs

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.core.util.Result
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.jca.PivPrivateKey
import com.yubico.yubikit.piv.jca.PivProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate
import kotlin.coroutines.suspendCoroutine

data class YubiKeyAction(
    val message: String,
    val action: suspend (Result<YubiKeyDevice, Exception>) -> Unit
)


class ClientCertificatesViewModel : ViewModel() {

    init {
        // Needed for PIV private keys to work
        Security.insertProviderAt(PivProvider { callback ->
            _pendingYubiKeyAction.postValue(YubiKeyAction("PIV private key required") { result ->
                try {
                    result.value.requestConnection(SmartCardConnection::class.java) {
                        callback.invoke(Result.of {
                            PivSession(it.value)
                        })
                    }
                } catch (e: Exception) {
                    callback.invoke(Result.failure(e))
                }
            })
        }, 1)
    }

    val url = MutableLiveData("")
    //val url = MutableLiveData("https://webauthntest.azurewebsites.net/")
    //val url = MutableLiveData("https://demo.yubico.com/")

    val useNfc = MutableLiveData(true)
    val usbYubiKey = MutableLiveData<UsbYubiKeyDevice?>()

    private val _pendingYubiKeyAction = MutableLiveData<YubiKeyAction?>()
    val pendingYubiKeyAction: LiveData<YubiKeyAction?> = _pendingYubiKeyAction

    suspend fun provideYubiKey(result: Result<YubiKeyDevice, Exception>) =
        withContext(Dispatchers.IO) {
            pendingYubiKeyAction.value?.let {
                _pendingYubiKeyAction.postValue(null)
                it.action.invoke(result)
            }
        }

    /**
     * Requests a PIV session, and uses it to produce some result
     */
    suspend fun <T> usePiv(title: String, action: (PivSession) -> T) =
        suspendCoroutine { outer ->
            _pendingYubiKeyAction.postValue(YubiKeyAction(title) { yubiKey ->
                outer.resumeWith(runCatching {
                    suspendCoroutine { inner ->
                        yubiKey.value.requestConnection(SmartCardConnection::class.java) {
                            inner.resumeWith(runCatching {
                                action.invoke(PivSession(it.value))
                            })
                        }
                    }
                })
            })
        }
}
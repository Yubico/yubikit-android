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
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.util.Result
import com.yubico.yubikit.fido.android.YubiKitFidoClient.Companion.extensions
import com.yubico.yubikit.fido.client.BasicWebAuthnClient
import com.yubico.yubikit.fido.ctap.Ctap2Session
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

typealias YubiKeyAction = suspend (Result<YubiKeyDevice, Exception>) -> Unit

class MainViewModel : ViewModel() {

    private val _nfcAvailable = MutableLiveData(false)
    val isNfcAvailable: LiveData<Boolean> = _nfcAvailable

    private val _device = MutableLiveData<YubiKeyDevice?>()
    val device: LiveData<YubiKeyDevice?> = _device

    private val _pendingYubiKeyAction = MutableLiveData<YubiKeyAction?>()

    val isUsb: Boolean
        get() = _device.value is UsbYubiKeyDevice

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

    suspend fun waitForKeyRemoval() = suspendCoroutine { continuation ->
        when (val dev = _device.value) {
            is NfcYubiKeyDevice -> dev.remove { continuation.resume(Unit) }
            else -> continuation.resume(Unit)
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
                Ctap2Session.create(usbDevice) {
                    inner.resume(runCatching {
                        extensions?.let { ext ->
                            action.invoke(BasicWebAuthnClient(it.value, ext))
                        } ?: action.invoke(BasicWebAuthnClient(it.value))
                    })
                }
            }
        }
        return suspendCoroutine { outer ->
            _pendingYubiKeyAction.postValue { result ->
                outer.resumeWith(runCatching {
                    suspendCoroutine { inner ->
                        Ctap2Session.create(result.value) {
                            inner.resume(runCatching {
                                extensions?.let { ext ->
                                    action.invoke(BasicWebAuthnClient(it.value, ext))
                                } ?: action.invoke(BasicWebAuthnClient(it.value))
                            })
                        }
                    }
                })
            }
        }
    }
}
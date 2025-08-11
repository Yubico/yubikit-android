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

    private var _nfcAvailable = MutableLiveData<Boolean>(false)
    private var _device = MutableLiveData<YubiKeyDevice?>()
    private var _pendingYubiKeyAction = MutableLiveData<YubiKeyAction?>()

    val isNfcAvailable: LiveData<Boolean> = _nfcAvailable

    val isUsb: Boolean
        get() = _device.value is UsbYubiKeyDevice

    fun setNfcAvailable(value: Boolean) {
        _nfcAvailable.postValue(value)
    }

    suspend fun provideYubiKey(device: YubiKeyDevice) =
        _pendingYubiKeyAction.value?.let {
            _pendingYubiKeyAction.postValue(null)
            it.invoke(Result.success(device))
        }.also {
            (device as? UsbYubiKeyDevice?)?.let {
                it.setOnClosed {
                    _device.postValue(null)
                }
            }
        }.also {
            _device.postValue(device)
        }

    suspend fun waitForKeyRemoval() {
        suspendCoroutine { continuation ->
            if (_device.value is NfcYubiKeyDevice) {
                (_device.value as? NfcYubiKeyDevice?)?.let {
                    it.remove {
                        continuation.resume(Unit)
                    }
                }
            } else {
                // don't wait for removal on USB
                continuation.resume(Unit)
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
        (_device.value as? UsbYubiKeyDevice?)?.let {
            return suspendCoroutine { inner ->
                Ctap2Session.create(it) {
                    inner.resume(
                        kotlin.runCatching {
                            if (extensions == null)
                                action.invoke(BasicWebAuthnClient(it.value))
                            else
                                action.invoke(
                                    BasicWebAuthnClient(
                                        it.value,
                                        extensions!!
                                    )
                                )
                        }
                    )
                }
            }
        }

        return suspendCoroutine { outer ->
            _pendingYubiKeyAction.postValue { result ->
                outer.resumeWith(runCatching {
                    suspendCoroutine { inner ->
                        Ctap2Session.create(result.value) {
                            inner.resume(
                                kotlin.runCatching {
                                    extensions?.let { extensions ->
                                        action.invoke(
                                            BasicWebAuthnClient(
                                                it.value,
                                                extensions
                                            )
                                        )
                                    } ?: run {
                                        action.invoke(BasicWebAuthnClient(it.value))
                                    }
                                })
                        }
                    }
                })
            }
        }
    }
}
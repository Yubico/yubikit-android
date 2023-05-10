/*
 * Copyright (C) 2022-2023 Yubico.
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

package com.yubico.yubikit.android.app.ui.oath

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.smartcard.ApduException
import com.yubico.yubikit.core.smartcard.SW
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.oath.Code
import com.yubico.yubikit.oath.Credential
import com.yubico.yubikit.oath.OathSession
import com.yubico.yubikit.oath.OathType

class OathViewModel : YubiKeyViewModel<OathSession>() {
    private val _oathDeviceId = MutableLiveData<String?>()
    val oathDeviceId: LiveData<String?> = _oathDeviceId

    private val _credentials = MutableLiveData<Map<Credential, Code?>?>()
    val credentials: LiveData<Map<Credential, Code?>?> = _credentials

    var password: Pair<String, CharArray>? = null

    private var isNfc = false
    override fun getSession(device: YubiKeyDevice, onError: (Throwable) -> Unit, callback: (OathSession) -> Unit) {
        runCatching {
            device.openConnection(SmartCardConnection::class.java).use {
                isNfc = it.transport == Transport.NFC
                callback(OathSession(it))
            }
        }.onFailure(onError)
    }

    override fun OathSession.updateState() {
        _oathDeviceId.postValue(deviceId)

        if (isLocked) {
            password?.let {
                it.first == deviceId && unlock(it.second)
            }
        }

        val codes = try {
            calculateCodes()
        } catch (e: ApduException) {
            when (e.sw) {
                SW.MEMORY_ERROR -> credentials.associateWith {
                    when {
                        isNfc && it.oathType == OathType.TOTP -> calculateCode(it)
                        else -> null
                    }
                }
                else -> throw e
            }
        }
        _credentials.postValue(codes)
    }
}
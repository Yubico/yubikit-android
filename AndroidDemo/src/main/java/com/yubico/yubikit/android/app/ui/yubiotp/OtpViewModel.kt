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

package com.yubico.yubikit.android.app.ui.yubiotp

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.yubiotp.ConfigurationState
import com.yubico.yubikit.yubiotp.YubiOtpSession

class OtpViewModel : YubiKeyViewModel<YubiOtpSession>() {
    private val slotStatus = MutableLiveData<ConfigurationState?>()
    val slotConfigurationState: LiveData<ConfigurationState?> = slotStatus

    override fun getSession(
        device: YubiKeyDevice,
        onError: (Throwable) -> Unit,
        callback: (YubiOtpSession) -> Unit,
    ) {
        YubiOtpSession.create(device) {
            try {
                callback(it.value)
            } catch (e: Throwable) {
                onError(e)
            }
        }
    }

    override fun YubiOtpSession.updateState() {
        slotStatus.postValue(configurationState)
    }
}

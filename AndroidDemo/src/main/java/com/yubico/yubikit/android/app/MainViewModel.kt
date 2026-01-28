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

package com.yubico.yubikit.android.app

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.yubico.yubikit.core.YubiKeyDevice
import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.Executors

class MainViewModel : ViewModel() {
    val singleDispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

    private val _handleYubiKey = MutableLiveData(true)
    val handleYubiKey: LiveData<Boolean> = _handleYubiKey

    fun setYubiKeyListenerEnabled(enabled: Boolean) {
        _handleYubiKey.postValue(enabled)
    }

    val yubiKey = MutableLiveData<YubiKeyDevice?>()
}

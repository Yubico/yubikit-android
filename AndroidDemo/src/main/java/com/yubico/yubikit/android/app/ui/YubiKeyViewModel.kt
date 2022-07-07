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

package com.yubico.yubikit.android.app.ui

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.yubico.yubikit.core.YubiKeyDevice
import java.io.Closeable

abstract class YubiKeyViewModel<Session : Closeable> : ViewModel() {
    private val _result = MutableLiveData<Result<String?>>(Result.success(null))
    val result: LiveData<Result<String?>> = _result

    val pendingAction = MutableLiveData<(Session.() -> String?)?>()

    abstract fun getSession(device: YubiKeyDevice, onError: (Throwable) -> Unit, callback: (Session) -> Unit)
    abstract fun Session.updateState()

    fun onYubiKeyDevice(device: YubiKeyDevice) {
        getSession(device, { _result.postValue(Result.failure(it)) }) { session ->
            pendingAction.value?.let {
                _result.postValue(Result.runCatching { it(session) })
                pendingAction.postValue(null)
            }

            session.updateState()
        }
    }

    fun postResult(result: Result<String?>) {
        _result.postValue(result)
    }

    fun clearResult() {
        _result.value.let {
            if (it != null && (it.isFailure || it.getOrNull() != null)) {
                _result.postValue(Result.success(null))
            }
        }
    }
}
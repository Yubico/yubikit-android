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

package com.yubico.yubikit.demo.otp

import androidx.lifecycle.LiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.yubico.yubikit.demo.fido.arch.ErrorLiveEvent
import com.yubico.yubikit.demo.fido.arch.SingleLiveEvent

private const val TAG = "OtpViewModel"
class OtpViewModel(private val validator: YubiCloudValidator) : ViewModel() {

    private val _error = ErrorLiveEvent(TAG)
    val error : LiveData<Throwable> = _error

    private val _success = SingleLiveEvent<Void>()
    val success: LiveData<Void> = _success

    fun validate(key: String) {
        validator.verify(key, object : YubiCloudValidator.Listener {
            override fun onSuccess() {
                _success.call()
            }

            override fun onFailure(e: Throwable) {
                _error.value = e
            }
        })
    }

    /**
     * Class factory to create instance of {@link OtpViewModel}
     */
    class Factory(private val validator: YubiCloudValidator) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return OtpViewModel(validator) as T
        }
    }
}
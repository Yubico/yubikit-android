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

package com.yubico.yubikit.demo.mgmt

import androidx.lifecycle.LiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.apdu.ApduException
import com.yubico.yubikit.demo.YubikeyViewModel
import com.yubico.yubikit.demo.fido.arch.SingleLiveEvent
import com.yubico.yubikit.management.DeviceConfiguration
import com.yubico.yubikit.management.ManagementApplication
import com.yubico.yubikit.transport.YubiKeySession
import com.yubico.yubikit.utils.Logger
import java.io.IOException
import java.util.concurrent.Executors

class ManagementViewModel(yubiKitManager: YubiKitManager) : YubikeyViewModel(yubiKitManager) {

    /**
     * For execution of communication with yubikey on background
     * Using single thread to avoid thread racing for different commands
     */
    private val executorService = Executors.newSingleThreadExecutor()

    private val _deviceConfiguration = SingleLiveEvent<DeviceConfiguration>()
    val deviceConfiguration : LiveData<DeviceConfiguration> = _deviceConfiguration

    private val _updated = SingleLiveEvent<Boolean>()
    val updated : LiveData<Boolean> = _updated

    override fun YubiKeySession.executeDemoCommands() {
        executeOnBackgroundThread { application ->
            val config = _deviceConfiguration.value
            if (config != null && config.isChanged) {
                when {
                    application.version.major >= 5 -> {
                        application.writeConfiguration(config, true)
                        _deviceConfiguration.postValue(config)
                        _updated.postValue(true)
                    }
                    else -> {
                        // set mode might not be able to turn off/on some capabilities
                        // so it'requires reading from device it's real state to revert changes that couldn't be saved
                        application.setMode(config)
                        _updated.postValue(true)
                    }
                }
            } else {
                _deviceConfiguration.postValue(application.readConfiguration())
            }
        }
    }

    private fun YubiKeySession.executeOnBackgroundThread(runCommand: (managementApplication: ManagementApplication) -> Unit) {
        executorService.execute {
            try {
                Logger.d("Select MGMT application")
                ManagementApplication(this).use {
                    // run provided command/operation (read or write config)
                    runCommand(it)
                }
            } catch (e: IOException) {
                postError(e)
            } catch (e: ApduException) {
                postError(e)
            }
        }
    }

    fun saveConfig(config: DeviceConfiguration) {
        if (config.isChanged) {
            executeDemoCommands()
        }
    }

    fun releaseConfig() {
        _deviceConfiguration.postValue(null)
        _updated.postValue(false)
    }

    /**
     * Class factory to create instance of {@link OathViewModel}
     */
    class Factory(private val yubikitManager: YubiKitManager) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return ManagementViewModel(yubikitManager) as T
        }
    }

}
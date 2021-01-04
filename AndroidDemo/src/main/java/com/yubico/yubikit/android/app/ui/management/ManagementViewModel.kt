package com.yubico.yubikit.android.app.ui.management

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.management.DeviceInfo
import com.yubico.yubikit.management.ManagementSession
import java.io.IOException


class ManagementViewModel : YubiKeyViewModel<ManagementSession>() {
    private val _deviceInfo = MutableLiveData<DeviceInfo?>()
    val deviceInfo: LiveData<DeviceInfo?> = _deviceInfo

    override fun getSession(device: YubiKeyDevice, onError: (Throwable) -> Unit, callback: (ManagementSession) -> Unit) {
        ManagementSession.create(device) {
            try {
                callback(it.value)
            } catch (e: IOException) {
                onError(e)
            }
        }
    }

    override fun ManagementSession.updateState() {
        _deviceInfo.postValue(deviceInfo)
    }
}
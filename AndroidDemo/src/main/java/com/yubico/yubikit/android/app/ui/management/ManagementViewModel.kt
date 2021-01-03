package com.yubico.yubikit.android.app.ui.management

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.management.DeviceInfo
import com.yubico.yubikit.management.ManagementSession
import java.lang.Exception


class ManagementViewModel : YubiKeyViewModel<ManagementSession>() {
    private val _deviceInfo = MutableLiveData<DeviceInfo?>()
    val deviceInfo: LiveData<DeviceInfo?> = _deviceInfo

    override fun getSession(device: YubiKeyDevice, onError: (Throwable) -> Unit, callback: (ManagementSession) -> Unit) {
        ManagementSession.create(device, object : ManagementSession.SessionCallback() {
            override fun onSession(session: ManagementSession) {
                callback(session)
            }

            override fun onError(error: Exception) {
                onError(error)
            }
        })
    }

    override fun ManagementSession.updateState() {
        _deviceInfo.postValue(deviceInfo)
    }
}
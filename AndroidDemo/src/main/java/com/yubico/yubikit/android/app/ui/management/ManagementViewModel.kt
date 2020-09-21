package com.yubico.yubikit.android.app.ui.management

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.otp.OtpConnection
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.management.DeviceInfo
import com.yubico.yubikit.management.ManagementSession
import com.yubico.yubikit.core.Logger
import java.io.IOException

class NonClosingManagementSession(connection: OtpConnection) : ManagementSession(connection) {
    override fun close() {
        Logger.d("Keeping session open")
    }

    fun doClose() {
        Logger.d("Closing session")
        super.close()
    }
}

class ManagementViewModel : YubiKeyViewModel<ManagementSession>() {
    private val _deviceInfo = MutableLiveData<DeviceInfo?>()
    val deviceInfo: LiveData<DeviceInfo?> = _deviceInfo

    override fun getSession(device: YubiKeyDevice): ManagementSession = when {
        device.supportsConnection(SmartCardConnection::class.java) -> ManagementSession(device.openConnection(SmartCardConnection::class.java))
        // Keep the application open over OTP, as closing it causes the device to re-enumerate
        device.supportsConnection(OtpConnection::class.java) -> NonClosingManagementSession(device.openConnection(OtpConnection::class.java))
        else -> throw IOException("No interface available for Management")
    }

    override fun ManagementSession.updateState() {
        _deviceInfo.postValue(deviceInfo)
    }
}
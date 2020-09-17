package com.yubico.yubikit.android.app.ui.mgmt

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.core.YubiKeySession
import com.yubico.yubikit.core.otp.OtpConnection
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.mgmt.DeviceInfo
import com.yubico.yubikit.mgmt.ManagementApplication
import com.yubico.yubikit.core.Logger
import java.io.IOException

class NonClosingManagementApplication(connection: OtpConnection) : ManagementApplication(connection) {
    override fun close() {
        Logger.d("Keeping application open")
    }

    fun doClose() {
        Logger.d("Closing application")
        super.close()
    }
}

class MgmtViewModel : YubiKeyViewModel<ManagementApplication>() {
    private val _deviceInfo = MutableLiveData<DeviceInfo?>()
    val deviceInfo: LiveData<DeviceInfo?> = _deviceInfo

    override fun getApp(session: YubiKeySession): ManagementApplication = when {
        session.supportsConnection(SmartCardConnection::class.java) -> ManagementApplication(session.openConnection(SmartCardConnection::class.java))
        // Keep the application open over OTP, as closing it causes the device to re-enumerate
        session.supportsConnection(OtpConnection::class.java) -> NonClosingManagementApplication(session.openConnection(OtpConnection::class.java))
        else -> throw IOException("No interface available for Management")
    }

    override fun ManagementApplication.updateState() {
        _deviceInfo.postValue(getDeviceInfo())
    }
}
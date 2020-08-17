package com.yubico.yubikit.android.app.ui.mgmt

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.YubiKeySession
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.android.transport.usb.UsbSession
import com.yubico.yubikit.mgmt.DeviceInfo
import com.yubico.yubikit.mgmt.ManagementApplication
import java.io.IOException

class MgmtViewModel : YubiKeyViewModel<ManagementApplication>() {
    private val _deviceInfo = MutableLiveData<DeviceInfo?>()
    val deviceInfo: LiveData<DeviceInfo?> = _deviceInfo

    override fun getApp(session: YubiKeySession): ManagementApplication = when (session) {
        is UsbSession -> when {
            session.isIso7816Available -> ManagementApplication(session.openIso7816Connection())
            session.isOtpAvailable -> ManagementApplication(session.openOtpConnection())
            else -> throw IOException("No interface available for Management")
        }
        else -> ManagementApplication(session.openIso7816Connection())
    }

    override fun ManagementApplication.updateState() {
        _deviceInfo.postValue(readDeviceInfo())
    }
}
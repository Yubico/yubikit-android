package com.yubico.yubikit.android.app.ui.otp

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.keyboard.OtpConnection
import com.yubico.yubikit.android.YubiKeySession
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.android.transport.usb.UsbSession
import com.yubico.yubikit.otp.Status
import com.yubico.yubikit.otp.YubiKeyConfigurationApplication
import com.yubico.yubikit.utils.Logger
import java.io.IOException

class NonClosingYubiKeyConfigurationApplication(connection: OtpConnection) : YubiKeyConfigurationApplication(connection) {
    override fun close() {
        Logger.d("Keeping application open")
    }

    fun doClose() {
        Logger.d("Closing application")
        super.close()
    }
}

class OtpViewModel : YubiKeyViewModel<YubiKeyConfigurationApplication>() {
    private var ignoreUsb = false
    private var appRef: NonClosingYubiKeyConfigurationApplication? = null

    private val _slotStatus = MutableLiveData<Status?>()
    val slotStatus: LiveData<Status?> = _slotStatus

    override fun getApp(session: YubiKeySession): YubiKeyConfigurationApplication = when (session) {
        is UsbSession -> when {
            ignoreUsb && appRef != null -> appRef!!
            session.isOtpAvailable -> NonClosingYubiKeyConfigurationApplication(session.openOtpConnection()).apply { appRef = this }
            session.isIso7816Available -> YubiKeyConfigurationApplication(session.openIso7816Connection())
            else -> throw IOException("No interface available for Management")
        }
        else -> YubiKeyConfigurationApplication(session.openIso7816Connection())
    }

    override fun YubiKeyConfigurationApplication.updateState() {
        _slotStatus.postValue(status)
    }

    fun releaseYubiKey() {
        appRef?.doClose()
        //ignoreUsb = true
    }

    fun resumeUsbCapture() {
        ignoreUsb = false
    }
}
package com.yubico.yubikit.android.app.ui.otp

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.core.YubiKeySession
import com.yubico.yubikit.core.otp.OtpConnection
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.otp.ConfigState
import com.yubico.yubikit.otp.YubiOtpApplication
import com.yubico.yubikit.core.Logger
import java.io.IOException

class NonClosingYubiOtpApplication(connection: OtpConnection) : YubiOtpApplication(connection) {
    override fun close() {
        Logger.d("Keeping application open")
    }

    fun doClose() {
        Logger.d("Closing application")
        super.close()
    }
}

class OtpViewModel : YubiKeyViewModel<YubiOtpApplication>() {
    private var ignoreUsb = false
    private var appRef: NonClosingYubiOtpApplication? = null

    private val _slotStatus = MutableLiveData<ConfigState?>()
    val slotConfigState: LiveData<ConfigState?> = _slotStatus

    override fun getApp(session: YubiKeySession): YubiOtpApplication = when {
        ignoreUsb && appRef != null -> appRef!!
        session.supportsConnection(OtpConnection::class.java) -> NonClosingYubiOtpApplication(session.openConnection(OtpConnection::class.java)).apply { appRef = this }
        session.supportsConnection(SmartCardConnection::class.java) -> YubiOtpApplication(session.openConnection(SmartCardConnection::class.java))
        else -> throw IOException("No interface available for Management")
    }

    override fun YubiOtpApplication.updateState() {
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
package com.yubico.yubikit.android.app.ui.otp

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.otp.OtpConnection
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.otp.ConfigState
import com.yubico.yubikit.otp.YubiOtpSession
import com.yubico.yubikit.core.Logger
import java.io.IOException

class NonClosingYubiOtpSession(connection: OtpConnection) : YubiOtpSession(connection) {
    override fun close() {
        Logger.d("Keeping application open")
    }

    fun doClose() {
        Logger.d("Closing application")
        super.close()
    }
}

class OtpViewModel : YubiKeyViewModel<YubiOtpSession>() {
    private var ignoreUsb = false
    private var sessionRef: NonClosingYubiOtpSession? = null

    private val _slotStatus = MutableLiveData<ConfigState?>()
    val slotConfigState: LiveData<ConfigState?> = _slotStatus

    override fun getSession(device: YubiKeyDevice): YubiOtpSession = when {
        ignoreUsb && sessionRef != null -> sessionRef!!
        device.supportsConnection(OtpConnection::class.java) -> NonClosingYubiOtpSession(device.openConnection(OtpConnection::class.java)).apply { sessionRef = this }
        device.supportsConnection(SmartCardConnection::class.java) -> YubiOtpSession(device.openConnection(SmartCardConnection::class.java))
        else -> throw IOException("No interface available for Management")
    }

    override fun YubiOtpSession.updateState() {
        _slotStatus.postValue(status)
    }

    fun releaseYubiKey() {
        sessionRef?.doClose()
        //ignoreUsb = true
    }

    fun resumeUsbCapture() {
        ignoreUsb = false
    }
}
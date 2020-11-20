package com.yubico.yubikit.android.app.ui.yubiotp

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.Logger
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.otp.OtpConnection
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.yubiotp.ConfigurationState
import com.yubico.yubikit.yubiotp.YubiOtpSession
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
    private var sessionRef: NonClosingYubiOtpSession? = null

    private val _slotStatus = MutableLiveData<ConfigurationState?>()
    val slotConfigurationState: LiveData<ConfigurationState?> = _slotStatus

    override fun getSession(device: YubiKeyDevice): YubiOtpSession = when {
        sessionRef != null -> sessionRef!!
        device.supportsConnection(OtpConnection::class.java) -> {
            val connection = device.openConnection(OtpConnection::class.java)
            try {
                NonClosingYubiOtpSession(connection).apply { sessionRef = this }
            } catch (e: Exception) {
                connection.close()
                throw e
            }
        }
        device.supportsConnection(SmartCardConnection::class.java) -> {
            val connection = device.openConnection(SmartCardConnection::class.java)
            try {
                YubiOtpSession(connection)
            } catch (e: Exception) {
                connection.close()
                throw e
            }
        }
        else -> throw IOException("No interface available for OTP")
    }

    override fun YubiOtpSession.updateState() {
        _slotStatus.postValue(configurationState)
    }

    fun releaseYubiKey() {
        sessionRef?.let {
            it.doClose()
            sessionRef = null
        }
    }
}
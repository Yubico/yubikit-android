package com.yubico.yubikit.android.app.ui.yubiotp

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.yubiotp.ConfigurationState
import com.yubico.yubikit.yubiotp.YubiOtpSession
import java.lang.Exception


class OtpViewModel : YubiKeyViewModel<YubiOtpSession>() {
    private val _slotStatus = MutableLiveData<ConfigurationState?>()
    val slotConfigurationState: LiveData<ConfigurationState?> = _slotStatus

    override fun getSession(device: YubiKeyDevice, onError: (Throwable) -> Unit, callback: (YubiOtpSession) -> Unit) {
        YubiOtpSession.create(device, object : YubiOtpSession.SessionCallback() {
            override fun onSession(session: YubiOtpSession) {
                callback(session)
            }

            override fun onError(error: Exception) {
                onError(error)
            }
        })
    }

    override fun YubiOtpSession.updateState() {
        _slotStatus.postValue(configurationState)
    }
}
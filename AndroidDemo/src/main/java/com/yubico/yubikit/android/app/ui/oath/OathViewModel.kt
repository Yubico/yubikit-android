package com.yubico.yubikit.android.app.ui.oath

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.Version
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.smartcard.ApduException
import com.yubico.yubikit.core.smartcard.SW
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.oath.Code
import com.yubico.yubikit.oath.Credential
import com.yubico.yubikit.oath.OathSession
import com.yubico.yubikit.oath.OathType
import java.io.IOException

data class OathApplicationInfo(val version: Version, val deviceId: String, val hasAccessKey: Boolean)

class OathViewModel : YubiKeyViewModel<OathSession>() {
    private val _oathDeviceId = MutableLiveData<String?>()
    val oathDeviceId: LiveData<String?> = _oathDeviceId

    private val _credentials = MutableLiveData<Map<Credential, Code?>?>()
    val credentials: LiveData<Map<Credential, Code?>?> = _credentials

    var password: Pair<String, CharArray>? = null

    private var isNfc = false
    override fun getSession(device: YubiKeyDevice, onError: (Throwable) -> Unit, callback: (OathSession) -> Unit) {
        device.requestConnection(SmartCardConnection::class.java) {
            try {
                val connection = it.value
                isNfc = connection.transport == Transport.NFC
                callback(OathSession(connection))
            } catch (e: Throwable) {
                onError(e)
            }
        }
    }

    override fun OathSession.updateState() {
        _oathDeviceId.postValue(deviceId)

        if (hasAccessKey()) {
            password?.let {
                it.first == deviceId && unlock(it.second)
            }
        }

        val codes = try {
            calculateCodes()
        } catch (e: ApduException) {
            when (e.sw) {
                SW.MEMORY_ERROR -> credentials.map {
                    it to when {
                        isNfc && it.oathType == OathType.TOTP -> calculateCode(it)
                        else -> null
                    }
                }.toMap()
                else -> throw e
            }
        }
        _credentials.postValue(codes)
    }
}
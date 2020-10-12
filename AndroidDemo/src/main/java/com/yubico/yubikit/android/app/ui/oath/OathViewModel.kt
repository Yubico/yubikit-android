package com.yubico.yubikit.android.app.ui.oath

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.smartcard.ApduException
import com.yubico.yubikit.core.smartcard.SW
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.oath.*

class OathViewModel : YubiKeyViewModel<OathSession>() {
    private val _oathInfo = MutableLiveData<OathApplicationInfo?>()
    val oathInfo: LiveData<OathApplicationInfo?> = _oathInfo

    private val _credentials = MutableLiveData<Map<Credential, Code?>?>()
    val credentials: LiveData<Map<Credential, Code?>?> = _credentials

    var password: Pair<String, CharArray>? = null

    private var isNfc = false
    override fun getSession(device: YubiKeyDevice): OathSession {
        val connection = device.openConnection(SmartCardConnection::class.java)
        isNfc = connection.transport == Transport.NFC
        try {
            return OathSession(connection)
        } catch (e: Exception) {
            connection.close()
            throw e
        }
    }

    override fun OathSession.updateState() {
        _oathInfo.postValue(applicationInfo)

        if (applicationInfo.isAuthenticationRequired) {
            password?.let {
                it.first == applicationInfo.deviceId && validate(it.second)
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
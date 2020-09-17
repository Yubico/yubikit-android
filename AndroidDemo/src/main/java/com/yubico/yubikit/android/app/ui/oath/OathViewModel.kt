package com.yubico.yubikit.android.app.ui.oath

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.core.YubiKeySession
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.oath.Code
import com.yubico.yubikit.oath.Credential
import com.yubico.yubikit.oath.OathApplication
import com.yubico.yubikit.oath.OathApplicationInfo

class OathViewModel : YubiKeyViewModel<OathApplication>() {
    private val _oathInfo = MutableLiveData<OathApplicationInfo?>()
    val oathInfo: LiveData<OathApplicationInfo?> = _oathInfo

    private val _credentials = MutableLiveData<Map<Credential, Code>?>()
    val credentials: LiveData<Map<Credential, Code>?> = _credentials

    var password: Pair<String, CharArray>? = null

    override fun getApp(session: YubiKeySession) = OathApplication(session.openConnection(SmartCardConnection::class.java))

    override fun OathApplication.updateState() {
        _oathInfo.postValue(applicationInfo)

        if (applicationInfo.isAuthenticationRequired) {
            password?.let {
                it.first == applicationInfo.deviceId && validate(it.second)
            }
        }

        _credentials.postValue(calculateCodes())
    }
}
package com.yubico.yubikit.android.app.ui.web

import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.core.util.Result
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.jca.PivProvider
import java.security.Security

class WebViewModel : YubiKeyViewModel<PivSession>() {
    init {
        Security.addProvider(PivProvider { callback ->
            pendingAction.postValue {
                callback.invoke(Result.success(this))
                "PivSession provided"
            }
        })
    }

    override fun getSession(
        device: YubiKeyDevice,
        onError: (Throwable) -> Unit,
        callback: (PivSession) -> Unit
    ) {
        device.requestConnection(SmartCardConnection::class.java) {
            try {
                callback(PivSession(it.value))
            } catch (e: Throwable) {
                onError(e)
            }
        }
    }

    override fun PivSession.updateState() {

    }
}
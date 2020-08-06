package com.yubico.yubikit.android.app.ui.piv

import android.util.SparseArray
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.YubiKeySession
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.exceptions.ApduException
import com.yubico.yubikit.exceptions.BadResponseException
import com.yubico.yubikit.piv.PivApplication
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.utils.Logger
import java.security.cert.X509Certificate

private const val DEFAULT_AUTH_KEY = "010203040506070801020304050607080102030405060708"
private const val DEFAULT_PIN = "123456"
private const val DEFAULT_PUK = "12345678"

class PivViewModel : YubiKeyViewModel<PivApplication>() {
    /**
     * List of slots that we will show on demo UI
     */
    private val slots = listOf(Slot.AUTHENTICATION, Slot.SIGNATURE, Slot.KEY_MANAGEMENT, Slot.CARD_AUTH)

    /**
     * Map of credentials and codes received from keys (can be populated from multiple keys)
     */
    private val _certificates = MutableLiveData<SparseArray<X509Certificate>?>()
    val certificates: LiveData<SparseArray<X509Certificate>?> = _certificates

    var mgmtKey: ByteArray = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8)

    override fun getApp(session: YubiKeySession) = PivApplication(session.openIso7816Connection())

    override fun PivApplication.updateState() {
        _certificates.postValue(SparseArray<X509Certificate>().apply {
            slots.forEach {
                try {
                    put(it.value, getCertificate(it))
                } catch (e: ApduException) {
                    Logger.d("Missing certificate: $it")
                } catch (e: BadResponseException) {
                    // Malformed cert loaded? Ignore but log:
                    Logger.e("Failed getting certificate $it", e)
                }
            }
        })
    }
}
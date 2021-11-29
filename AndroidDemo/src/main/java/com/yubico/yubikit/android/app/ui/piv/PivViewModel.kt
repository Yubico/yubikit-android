package com.yubico.yubikit.android.app.ui.piv

import android.util.SparseArray
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.yubico.yubikit.android.app.ui.YubiKeyViewModel
import com.yubico.yubikit.core.Logger
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.BadResponseException
import com.yubico.yubikit.core.smartcard.ApduException
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.oath.OathSession
import com.yubico.yubikit.piv.ManagementKeyType
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.jca.Pin
import com.yubico.yubikit.piv.jca.PivManagerFactoryParameters
import com.yubico.yubikit.piv.jca.PivProvider
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URL
import java.security.Security
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

class PivViewModel : YubiKeyViewModel<PivSession>() {
    /**
     * List of slots that we will show on demo UI
     */
    private val slots = listOf(Slot.AUTHENTICATION, Slot.SIGNATURE, Slot.KEY_MANAGEMENT, Slot.CARD_AUTH)

    /**
     * Map of credentials and codes received from keys (can be populated from multiple keys)
     */
    private val _certificates = MutableLiveData<SparseArray<X509Certificate>?>()
    val certificates: LiveData<SparseArray<X509Certificate>?> = _certificates

    var mgmtKeyType = ManagementKeyType.TDES
    var mgmtKey: ByteArray = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8)

    init {
        Security.addProvider(PivProvider())
    }

    override fun getSession(device: YubiKeyDevice, onError: (Throwable) -> Unit, callback: (PivSession) -> Unit) {
        device.requestConnection(SmartCardConnection::class.java) {
            try {
                callback(PivSession(it.value))
            } catch(e: Throwable) {
                onError(e)
            }
        }
    }

    override fun PivSession.updateState() {
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

        val kmf = KeyManagerFactory.getInstance("X509", "YKPiv")
        kmf.init(PivManagerFactoryParameters(this, Pin("123456")))

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(kmf.keyManagers, null, null)

        val url = URL("https://dain.se:8443")
        val connection = url.openConnection() as HttpsURLConnection
        connection.sslSocketFactory = sslContext.socketFactory

        val html = BufferedReader(InputStreamReader(connection.inputStream)).readText()
        Logger.d("HTML: $html")
    }
}
package com.yubico.yubikit.android.app.ui.client_certs

import android.content.res.Resources
import android.graphics.Bitmap
import android.net.http.SslError
import android.util.Log
import android.webkit.ClientCertRequest
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.annotation.RequiresApi
import androidx.lifecycle.viewModelScope
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.android.app.ui.getSecret
import com.yubico.yubikit.piv.PinPolicy
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.jca.PivPrivateKey
import com.yubico.yubikit.piv.jca.PivProvider
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import java.security.KeyStore
import java.security.cert.X509Certificate

@RequiresApi(21)
class DemoWebViewClient(private val viewModel: ClientCertificatesViewModel) :
    WebViewClient() {

    companion object {
        const val TAG = "WebViewClient"
    }

    override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
        Log.d(TAG, "Browsing to $url")
        super.onPageStarted(view, url, favicon)
    }

    override fun onPageFinished(view: WebView, url: String) {
        Log.d(TAG, "Browsed to $url")
        super.onPageFinished(view, url)
    }

    private suspend fun getCertificates(resources: Resources) =
        viewModel.usePiv(resources.getString(R.string.client_certs_dialog_title_read_certs)) { piv: PivSession ->
            // We initialize a second PivProvider here to use with the KeyStore instance.
            // Unlike the one in MainViewModel which is registered as a system Provider,
            // this one will only be used synchronously with this instance of the PivSession.
            val keyStore = KeyStore.getInstance("YKPiv", PivProvider(piv))
            keyStore.load(null)
            listOf(
                Slot.AUTHENTICATION,
                Slot.SIGNATURE,
                Slot.KEY_MANAGEMENT,
                Slot.CARD_AUTH
            ).mapNotNull { slot ->
                // We avoid padding the PIN here since we're not sure we need it yet
                when (val entry = keyStore.getEntry(slot.stringAlias, null)) {
                    // All entries returned here should be PrivateKeyEntry's, or null
                    is KeyStore.PrivateKeyEntry ->
                        Pair(
                            entry.privateKey as PivPrivateKey,
                            entry.certificate as X509Certificate
                        )
                    else -> null
                }
            }
        }

    /**
     * Handles client certificate requests using PIV on a YubiKey
     */
    override fun onReceivedClientCertRequest(view: WebView, request: ClientCertRequest) {
        Log.d(TAG, "Client certificate request from ${request.host}")
        viewModel.viewModelScope.launch {
            try {
                val certificates = getCertificates(view.resources)
                // Select which certificate to use
                val index =
                    selectItem(
                        view.context,
                        view.resources.getString(R.string.client_certs_dialog_select_cert),
                        certificates
                    ) { (key, certificate) -> "${key.slot.stringAlias}: ${certificate.issuerDN.name}" }

                val (privateKey, certificate) = certificates[index]
                if (privateKey.pinPolicy != PinPolicy.NEVER) {
                    // Now that we know we might need the PIN, we ask the user for it
                    getSecret(view.context, R.string.client_certs_dialog_enter_pin)?.apply {
                        // ...and give it to the PrivateKey so that it can be used
                        privateKey.setPin(toCharArray())
                    } ?: throw CancellationException()
                }
                // When the private key is used, it will again require a YubiKey connection
                request.proceed(privateKey, arrayOf(certificate))
            } catch (e: Exception) {
                Log.e(TAG, "Error getting client certificate auth", e)
                request.cancel()
            }
        }
    }

    /**
     * Allows bypass of untrusted server certificates
     *
     * WARNING: For demonstration purposes only!
     * Don't allow this in production!
     */
    override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
        Log.d("YKBrowser", "Recoverable SSL error")
        val message = when (error.primaryError) {
            SslError.SSL_NOTYETVALID -> "The certificate is not yet valid"
            SslError.SSL_EXPIRED -> "The certificate is expired"
            SslError.SSL_IDMISMATCH -> "Hostname mismatch"
            SslError.SSL_UNTRUSTED -> "The certificate authority is not trusted"
            SslError.SSL_DATE_INVALID -> "The date of the certificate is invalid"
            else -> "A generic error occurred"
        }
        viewModel.viewModelScope.launch {
            if (confirmAction(
                    view.context,
                    "Connection may not be secure",
                    "The website ${error.url} has a certificate problem:\n\n${message}\n\nProceed anyway?"
                )
            ) {
                handler.proceed()
            } else {
                handler.cancel()
            }
        }
    }
}
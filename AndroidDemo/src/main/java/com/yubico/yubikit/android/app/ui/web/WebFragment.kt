package com.yubico.yubikit.android.app.ui.web

import android.content.Context
import android.graphics.Bitmap
import android.net.http.SslError
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.webkit.ClientCertRequest
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.android.app.databinding.FragmentWebBinding
import com.yubico.yubikit.android.app.ui.YubiKeyFragment
import com.yubico.yubikit.android.app.ui.getSecret
import com.yubico.yubikit.core.Logger
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.jca.PivPrivateKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class WebFragment : YubiKeyFragment<PivSession, WebViewModel>() {
    override val viewModel: WebViewModel by activityViewModels()

    private lateinit var certificate: X509Certificate
    private lateinit var slot: Slot
    private lateinit var binding: FragmentWebBinding

    //The PrivateKey returned in the webview will be retained for the duration of the app lifetime,
    // so we need to make it able to prompt for PIN even if the creating context is no longer available.
    private object ContextHolder {
        var context: Context? = null
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        ContextHolder.context = requireContext()
        binding = FragmentWebBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val stream: InputStream = ByteArrayInputStream(requireArguments().getByteArray("cert"))
        val cf = CertificateFactory.getInstance("X.509")
        certificate = cf.generateCertificate(stream) as X509Certificate
        slot = Slot.fromValue(requireArguments().getInt("slot"))

        binding.edittext.setText("https://dain.se/cert.html")

        binding.webview.settings.javaScriptEnabled = true
        binding.webview.settings.domStorageEnabled = true
        binding.webview.webViewClient = object : WebViewClient() {
            override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                Logger.d("Browsing to $url")
                binding.edittext.setText(url)
                super.onPageStarted(view, url, favicon)
            }

            override fun onReceivedClientCertRequest(view: WebView, request: ClientCertRequest) {
                Logger.d("onReceivedClientCertRequest $request")
                lifecycleScope.launch(Dispatchers.Main) {
                    getSecret(ContextHolder.context!!, R.string.enter_pin)?.let { pin ->
                        val privateKey =
                            PivPrivateKey.from(certificate.publicKey, slot, pin.toCharArray())
                        request.proceed(privateKey, arrayOf(certificate))
                    }
                }
            }

            override fun onReceivedSslError(
                view: WebView?,
                handler: SslErrorHandler,
                error: SslError?
            ) {
                Logger.d("SSL error $error")
                handler.proceed()
            }
        }

        binding.webview.loadUrl(binding.edittext.text.toString())

        binding.edittext.setOnEditorActionListener { _, actionId, _ ->
            when (actionId) {
                EditorInfo.IME_ACTION_DONE -> {
                    binding.webview.loadUrl(binding.edittext.text.toString())
                    true
                }
                else -> false
            }
        }
    }

    override fun onDestroy() {
        binding.webview.destroy()
        ContextHolder.context = null
        super.onDestroy()
    }
}
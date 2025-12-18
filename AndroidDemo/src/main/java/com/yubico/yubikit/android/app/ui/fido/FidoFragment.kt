/*
 * Copyright (C) 2025 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.android.app.ui.fido

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.webkit.CookieManager
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import androidx.webkit.WebViewFeature
import com.yubico.yubikit.android.app.databinding.FragmentFidoBinding
import com.yubico.yubikit.fido.android.YubiKitFidoClient
import com.yubico.yubikit.fido.android.withYubiKitWebauthn
import com.yubico.yubikit.fido.client.extensions.CredBlobExtension
import com.yubico.yubikit.fido.client.extensions.CredPropsExtension
import com.yubico.yubikit.fido.client.extensions.CredProtectExtension
import com.yubico.yubikit.fido.client.extensions.HmacSecretExtension
import com.yubico.yubikit.fido.client.extensions.LargeBlobExtension
import com.yubico.yubikit.fido.client.extensions.MinPinLengthExtension
import com.yubico.yubikit.fido.client.extensions.SignExtension
import org.slf4j.LoggerFactory

class FidoFragment : Fragment() {
    private val viewModel: FidoViewModel by activityViewModels()
    private var _binding: FragmentFidoBinding? = null
    val binding get() = _binding!!
    private val logger = LoggerFactory.getLogger(FidoFragment::class.java)
    private lateinit var yubiKitFidoClient: YubiKitFidoClient

    companion object {
        private val EXTENSIONS =
            listOf(
                CredPropsExtension(),
                CredBlobExtension(),
                CredProtectExtension(),
                HmacSecretExtension(),
                MinPinLengthExtension(),
                LargeBlobExtension(),
                SignExtension(),
            )
        private const val URL_PASSKEY = "https://passkey.org"
        private const val URL_WEBAUTHN_IO = "https://webauthn.io"
        private const val URL_YUBICO_DEMO = "https://demo.yubico.com/webauthn-developers"
        private const val URL_TLA_DEMO =
            "https://demo-ngotxvzeyaxb.tla.appl3-default-us1.k8s.dev.yubico.org/webauthn-developers"
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        yubiKitFidoClient = YubiKitFidoClient(this, EXTENSIONS)
        _binding = FragmentFidoBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onViewCreated(
        view: View,
        savedInstanceState: Bundle?,
    ) {
        super.onViewCreated(view, savedInstanceState)
        setupButtons()
        setupWebView()
        observeUrl()
    }

    private fun setupButtons() {
        binding.btnWeb1.setOnClickListener { viewModel.setUrl(URL_PASSKEY) }
        binding.btnWeb2.setOnClickListener { viewModel.setUrl(URL_WEBAUTHN_IO) }
        binding.btnWeb3.setOnClickListener { viewModel.setUrl(URL_YUBICO_DEMO) }
        binding.btnWeb4.setOnClickListener { viewModel.setUrl(URL_TLA_DEMO) }
        binding.btnClearCookies.setOnClickListener {
            CookieManager.getInstance().removeAllCookies {
                logger.info("Cookies cleared")
                viewModel.setUrl(viewModel.url.value ?: URL_PASSKEY)
            }
        }
    }

    private fun setupWebView() {
        binding.webView.settings.domStorageEnabled = true
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            binding.webView.withYubiKitWebauthn(lifecycleScope, yubiKitFidoClient)
        } else {
            logger.warn("Web Message Listener feature is not supported on this device.")
        }
        viewModel.setUrl(URL_PASSKEY) // Initial URL
    }

    private fun observeUrl() {
        viewModel.url.observe(viewLifecycleOwner) { url ->
            url?.let {
                logger.info("Loading URL: {}", it)
                binding.webView.loadUrl(it)
            }
        }
    }
}

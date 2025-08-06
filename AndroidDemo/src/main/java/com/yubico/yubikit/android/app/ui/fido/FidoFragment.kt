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
import com.yubico.yubikit.fido.android.YubiKitWebViewSupport.Companion.withYubiKitWebauthn
import com.yubico.yubikit.fido.client.extensions.CredBlobExtension
import com.yubico.yubikit.fido.client.extensions.CredPropsExtension
import com.yubico.yubikit.fido.client.extensions.CredProtectExtension
import com.yubico.yubikit.fido.client.extensions.HmacSecretExtension
import com.yubico.yubikit.fido.client.extensions.LargeBlobExtension
import com.yubico.yubikit.fido.client.extensions.MinPinLengthExtension
import com.yubico.yubikit.fido.client.extensions.SignExtension

class FidoFragment : Fragment() {
    private lateinit var binding: FragmentFidoBinding
    private lateinit var yubiKitFidoClient: YubiKitFidoClient

    private val extensions = listOf(
        CredPropsExtension(),
        CredBlobExtension(),
        CredProtectExtension(),
        HmacSecretExtension(),
        MinPinLengthExtension(),
        LargeBlobExtension(),
        SignExtension()
    )

    val viewModel: FidoViewModel by activityViewModels()


    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        yubiKitFidoClient = YubiKitFidoClient(this, extensions)
        binding = FragmentFidoBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.btnWeb1.setOnClickListener {
            viewModel.setUrl("https://passkey.org")
        }

        binding.btnWeb2.setOnClickListener {
            viewModel.setUrl("https://webauthn.io")
        }

        binding.btnWeb3.setOnClickListener {
            viewModel.setUrl("https://demo.yubico.com/webauthn-developers")
        }

        binding.btnWeb4.setOnClickListener {
            viewModel.setUrl("https://demo-ngotxvzeyaxb.tla.appl3-default-us1.k8s.dev.yubico.org/webauthn-developers")
        }

        binding.btnClearCookies.setOnClickListener {
            CookieManager.getInstance().removeAllCookies {
                viewModel.setUrl(viewModel.url.value)
            }
        }

        binding.webView.apply {
            settings.apply {
                domStorageEnabled = true
            }

            if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
                withYubiKitWebauthn(
                    lifecycleScope,
                    yubiKitFidoClient
                )
            } else {
                // not supported
            }

            viewModel.setUrl("https://passkey.org")
        }

        viewModel.url.observe(viewLifecycleOwner) { url ->
            if (url != null) {
                binding.webView.loadUrl(url)
            }
        }

    }
}
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
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import androidx.webkit.WebViewFeature
import com.yubico.yubikit.android.app.databinding.FragmentFidoBinding
import com.yubico.yubikit.fido.android.YubiKitFidoClient
import com.yubico.yubikit.fido.android.YubiKitWebViewSupport

class FidoFragment : Fragment() {
    private lateinit var binding: FragmentFidoBinding
    private lateinit var yubiKitFidoClient: YubiKitFidoClient

    val viewModel: FidoViewModel by activityViewModels()


    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        yubiKitFidoClient = YubiKitFidoClient(this)
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

        binding.webView.apply {
            settings.apply {
                javaScriptEnabled = true
                userAgentString =
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1"
                domStorageEnabled = true
            }

            if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
                YubiKitWebViewSupport.addWebAuthnSupport(
                    this,
                    requireActivity(),
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
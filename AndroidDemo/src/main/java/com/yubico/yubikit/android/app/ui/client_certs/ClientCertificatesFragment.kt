/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.android.app.ui.client_certs

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.app.MainViewModel
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.android.app.databinding.FragmentClientCertsBinding
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.util.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlin.coroutines.cancellation.CancellationException

@RequiresApi(21)
class ClientCertificatesFragment : Fragment() {

    val viewModel: ClientCertificatesViewModel by activityViewModels()
    private val appViewModel: MainViewModel by activityViewModels()
    private lateinit var yubikit: YubiKitManager
    private lateinit var binding: FragmentClientCertsBinding
    private lateinit var yubiKeyPrompt: AlertDialog

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        // this fragment has its own yubikey handler
        // disable yubiKey listener in main activity
        appViewModel.setYubiKeyListenerEnabled(false)

        binding = FragmentClientCertsBinding.inflate(inflater, container, false)

        // Handles YubiKey communication
        yubikit = YubiKitManager(requireContext())

        yubikit.startUsbDiscovery(UsbConfiguration()) { device ->
            // usbYubiKey keeps a reference to the currently connected YubiKey over USB
            viewModel.usbYubiKey.postValue(device)
            device.setOnClosed { viewModel.usbYubiKey.postValue(null) }

            lifecycleScope.launch(Dispatchers.Main) {
                viewModel.provideYubiKey(Result.success(device))
                // If we were asking the user to insert a YubiKey, close the dialog.
                yubiKeyPrompt.dismiss()
            }
        }

        // Dialog used to prompt the user to insert/tap a YubiKey
        yubiKeyPrompt = AlertDialog.Builder(requireContext())
            .setTitle(resources.getString(R.string.client_certs_dialog_title_insert_key))
            .setMessage(resources.getString(R.string.client_certs_dialog_msg_insert_key))
            .setOnCancelListener {
                lifecycleScope.launch {
                    viewModel.provideYubiKey(Result.failure(CancellationException("Cancelled by user")))
                }
            }
            .create()

        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        viewModel.pendingYubiKeyAction.observe(viewLifecycleOwner) { action ->
            if (action != null) {
                lifecycleScope.launch(Dispatchers.Main) {
                    val usbYubiKey = viewModel.usbYubiKey.value
                    if (usbYubiKey != null) {
                        viewModel.provideYubiKey(Result.success(usbYubiKey))
                        yubiKeyPrompt.dismiss()
                    } else {
                        val useNfc = viewModel.useNfc.value == true
                        yubiKeyPrompt.setTitle(action.message)
                        yubiKeyPrompt.setMessage(resources.getString(R.string.client_certs_dialog_msg_insert_key_now))
                        yubiKeyPrompt.show()
                        if (useNfc) {
                            // Listen on NFC
                            startNfc()
                        }
                    }
                }
            }
        }

        with(binding.webView) {
            settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
            }

            webViewClient = DemoWebViewClient(viewModel)
        }

        binding.go.setOnClickListener {
            WebView.clearClientCertPreferences {
                viewModel.url.postValue(URL)
            }
        }

        binding.help.setOnClickListener {
            WebView.clearClientCertPreferences {
                viewModel.url.postValue("")
            }
        }

        viewModel.url.observe(viewLifecycleOwner) {
            if (it.isEmpty()) {
                binding.webView.visibility = View.INVISIBLE
            } else {
                binding.webView.visibility = View.VISIBLE
                binding.webView.loadUrl(it)
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        // enable yubiKey listener in main activity
        appViewModel.setYubiKeyListenerEnabled(true)
    }


    private fun startNfc() {
        try {
            yubikit.startNfcDiscovery(NfcConfiguration(), requireActivity()) { nfcYubiKey ->
                lifecycleScope.launch(Dispatchers.Main) {
                    yubiKeyPrompt.setMessage(resources.getString(R.string.client_certs_dialog_msg_nfc_hold))
                    viewModel.provideYubiKey(Result.success(nfcYubiKey))
                    yubiKeyPrompt.setMessage(resources.getString(R.string.client_certs_dialog_msg_nfc_remove))
                    nfcYubiKey.remove {
                        lifecycleScope.launch(Dispatchers.Main) {
                            yubiKeyPrompt.dismiss()
                        }
                    }
                }
            }
        } catch (e: NfcNotAvailable) {
            viewModel.useNfc.value = false
        }
    }

    companion object {
        private const val URL = "https://client.badssl.com"
    }
}
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
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.app.databinding.FragmentClientCertsBinding
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.Logger
import com.yubico.yubikit.core.util.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlin.coroutines.cancellation.CancellationException

class ClientCertificatesFragment : Fragment() {

    val viewModel: ClientCertificatesViewModel by activityViewModels()
    private lateinit var yubikit: YubiKitManager
    private lateinit var binding: FragmentClientCertsBinding
    private lateinit var yubiKeyPrompt: AlertDialog

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        binding = FragmentClientCertsBinding.inflate(inflater, container, false)

        // Handles YubiKey communication
        yubikit = YubiKitManager(requireContext())

        yubikit.startUsbDiscovery(UsbConfiguration()) { device ->
            Logger.d("USB device attached $device")

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
            .setTitle("Insert YubiKey")
            .setMessage("Insert or tap your YubiKey")
            .setOnCancelListener {
                Log.d("YKBrowser", "CANCELLED")
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
                Log.d("YKBrowser", "Insert YubiKey...")
                lifecycleScope.launch(Dispatchers.Main) {
                    val usbYubiKey = viewModel.usbYubiKey.value
                    if (usbYubiKey != null) {
                        viewModel.provideYubiKey(Result.success(usbYubiKey))
                        yubiKeyPrompt.dismiss()
                    } else {
                        val useNfc = viewModel.useNfc.value == true
                        yubiKeyPrompt.setTitle(action.message)
                        yubiKeyPrompt.setMessage("Insert or tap your YubiKey now")
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

            webViewClient = ClientCertsWebViewClient(viewModel)

            loadUrl("https://client.badssl.com")
        }
    }


    private fun startNfc() {
        try {
            yubikit.startNfcDiscovery(NfcConfiguration(), activity!!) { nfcYubiKey ->
                Log.d("YKBrowser", "NFC Session started $nfcYubiKey")
                lifecycleScope.launch(Dispatchers.Main) {
                    yubiKeyPrompt.setMessage("Hold your YubiKey still")
                    viewModel.provideYubiKey(Result.success(nfcYubiKey))
                    Log.d("YKBrowser", "Remove NFC now")
                    yubiKeyPrompt.setMessage("Remove your YubiKey")
                    nfcYubiKey.remove {
                        Log.d("YKBrowser", "YubiKey NFC removed")
                        lifecycleScope.launch(Dispatchers.Main) {
                            yubiKeyPrompt.dismiss()
                        }
                    }
                }
            }
        } catch (e: NfcNotAvailable) {
            viewModel.useNfc.value = false
            Log.e("YKBrowser", "Error starting NFC listening", e)
        }
    }
}
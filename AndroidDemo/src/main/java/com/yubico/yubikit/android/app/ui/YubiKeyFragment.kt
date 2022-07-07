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

package com.yubico.yubikit.android.app.ui

import android.app.AlertDialog
import android.os.Bundle
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import com.yubico.yubikit.android.app.MainViewModel
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.core.Logger
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.ApplicationNotAvailableException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.Closeable

abstract class YubiKeyFragment<App : Closeable, VM : YubiKeyViewModel<App>> : Fragment() {
    private val activityViewModel: MainViewModel by activityViewModels()
    protected abstract val viewModel: VM

    private lateinit var yubiKeyPrompt: AlertDialog
    private lateinit var emptyText: TextView

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        emptyText = view.findViewById(R.id.empty_view)
        emptyText.visibility = View.VISIBLE

        yubiKeyPrompt = AlertDialog.Builder(context)
                .setTitle("Insert YubiKey")
                .setMessage(R.string.need_yubikey)
                .setOnCancelListener { viewModel.pendingAction.value = null }
                .create()

        activityViewModel.yubiKey.observe(viewLifecycleOwner) {
            if (it != null) {
                onYubiKey(it)
            } else {
                emptyText.setText(R.string.need_yubikey)
            }
        }

        viewModel.result.observe(viewLifecycleOwner) { result ->
            result.onSuccess {
                it?.let {
                    Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
                }
            }.onFailure {
                Logger.e("Error:", it)
                Toast.makeText(context, it.message ?: "No message", Toast.LENGTH_SHORT).show()
                if (it is ApplicationNotAvailableException) {
                    emptyText.setText(R.string.app_missing)
                }
            }
            viewModel.clearResult()
        }

        viewModel.pendingAction.observe(viewLifecycleOwner) {
            if (it != null) {
                activityViewModel.yubiKey.value.let { device ->
                    if (device != null) {
                        onYubiKey(device)
                    } else {
                        yubiKeyPrompt.setMessage(resources.getString(R.string.hold_key))
                        yubiKeyPrompt.show()
                    }
                }
            }
        }
    }

    override fun onPause() {
        if (yubiKeyPrompt.isShowing) {
            yubiKeyPrompt.dismiss()
        }
        super.onPause()
    }

    private fun onYubiKey(it: YubiKeyDevice) {
        lifecycleScope.launch {
            withContext(activityViewModel.singleDispatcher) {
                viewModel.onYubiKeyDevice(it)

                if (it is NfcYubiKeyDevice) {
                    withContext(Dispatchers.Main) {
                        if (yubiKeyPrompt.isShowing) {
                            yubiKeyPrompt.setMessage(resources.getString(R.string.remove_key))
                        } else {
                            emptyText.setText(R.string.remove_key)
                        }
                    }
                    it.remove(yubiKeyPrompt::dismiss)
                } else if (yubiKeyPrompt.isShowing) {
                    yubiKeyPrompt.dismiss()
                }
                Unit
            }
        }
    }
}
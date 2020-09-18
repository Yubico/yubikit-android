package com.yubico.yubikit.android.app.ui

import android.app.AlertDialog
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Observer
import androidx.lifecycle.lifecycleScope
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.android.app.MainViewModel
import com.yubico.yubikit.android.app.R
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.core.ApplicationNotAvailableException
import com.yubico.yubikit.core.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.io.IOException

abstract class YubiKeyFragment<App : Closeable, VM : YubiKeyViewModel<App>> : Fragment() {
    protected val activityViewModel: MainViewModel by activityViewModels()
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

        activityViewModel.yubiKey.observe(viewLifecycleOwner, Observer {
            if (it != null) {
                onYubiKey(it)
            } else {
                emptyText.setText(R.string.need_yubikey)
            }
        })

        viewModel.result.observe(viewLifecycleOwner, Observer { result ->
            result.onSuccess {
                it?.let {
                    Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
                }
            }.onFailure {
                Logger.e("Error:", it)
                Toast.makeText(context, it.message, Toast.LENGTH_SHORT).show()
                if (it is ApplicationNotAvailableException) {
                    emptyText.setText(R.string.app_missing)
                }
            }
            viewModel.clearResult()
        })

        viewModel.pendingAction.observe(viewLifecycleOwner, Observer {
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
        })
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
                    // Wait for the YubiKey to be removed before returning to avoid triggering a new tag discovery.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        NfcAdapter.getDefaultAdapter(context).ignore(
                                it.tag, 250, { yubiKeyPrompt.dismiss() }, null)
                    } else {
                        // Busy-wait for removal
                        @Suppress("BlockingMethodInNonBlockingContext")
                        try {
                            val isoDep = IsoDep.get(it.tag)
                            isoDep.connect()
                            while (isoDep.isConnected) {
                                Thread.sleep(250)
                            }
                        } catch (e: InterruptedException) {
                            //Ignore
                        } catch (e: IOException) {
                            //Ignore
                        }
                        yubiKeyPrompt.dismiss()
                    }
                } else if (yubiKeyPrompt.isShowing) {
                    yubiKeyPrompt.dismiss()
                }
                Unit
            }
        }
    }
}
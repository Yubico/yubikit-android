/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.demo.raw

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.*
import com.google.android.material.snackbar.Snackbar
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.apdu.ApduCodeException
import com.yubico.yubikit.apdu.ApduException
import com.yubico.yubikit.demo.BaseYubikeyFragment
import com.yubico.yubikit.demo.R
import com.yubico.yubikit.demo.YubikeyViewModel
import com.yubico.yubikit.demo.settings.Ramps
import com.yubico.yubikit.exceptions.NfcDisabledException
import com.yubico.yubikit.exceptions.NfcNotFoundException
import com.yubico.yubikit.exceptions.NoPermissionsException
import com.yubico.yubikit.transport.nfc.NfcDeviceManager
import kotlinx.android.synthetic.main.fragment_smartcard.*
import java.io.IOException
import java.lang.StringBuilder

/**
 *  This demo shows how to read a certificate from the key PIV application, loaded on slot 9c, , using the raw command interface from YubiKit.
 *  Notes:
 *      1. The key should be connected to the device before clicking the "Run demo" button.
 *      2. Runs on background queue in order to not lock the calling thread
 *      3. This code requires a certificate to be added to the key on slot 9c:
 *  - The certificate to test with is provided in keystore/cert.der
 *  - Run: yubico-piv-tool -s9c -icert.der -KDER -averify -aimport-cert
 *
 */
class YubikeySmartcardFragment : BaseYubikeyFragment(TAG) {
    // this view can be per fragment because we're not sharing it's data with any other activity or fragment
    private val viewModel: YubikeySmartcardViewModel by lazy {
        ViewModelProviders.of(this,
                YubikeySmartcardViewModel.Factory(YubiKitManager(activity!!.applicationContext), Settings(activity!!.applicationContext)))
                .get(YubikeySmartcardViewModel::class.java)
    }

    override fun getViewModel(): YubikeyViewModel {
        return viewModel
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_smartcard, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        viewModel.log.observe(viewLifecycleOwner, Observer {
            it?.run {
                Log.d(TAG, it)
                log.text = StringBuilder(log.text).append("\n").append(it).toString()
            }
        })

        run_demo.setOnClickListener {
            viewModel.executeDemoCommands()
        }
    }

    override fun onError(throwable: Throwable) {
        when (throwable) {
            is ApduCodeException -> log.text = StringBuilder(log.text).append("\n Error: ").append(Integer.toHexString(throwable.statusCode)).toString()
            is ApduException -> log.text = StringBuilder(log.text).append("\n Error: ").append(throwable.message).toString()
            else -> {
                val message = throwable.message ?: "No connection found"
                log.text = message
            }
        }
        activity?.invalidateOptionsMenu()
    }

    override fun onUsbSession(hasPermissions: Boolean) {
        if (hasPermissions) {
            log.text = "discovered yubikey via usb"
        }
    }

    override fun onNfcSession() {
        log.text = "discovered yubikey via nfc"
    }


    private class Settings(private val context: Context) : ISettings {
        override val connectionTimeout: Int
            get() = Ramps.CONNECTION_TIMEOUT.getValue(context) as Int
    }
    companion object {

        const val TAG = "YubikeySmartcardFragment"

    }
}
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

package com.yubico.yubikit.demo

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleObserver
import androidx.lifecycle.Observer
import androidx.lifecycle.OnLifecycleEvent
import com.google.android.material.snackbar.Snackbar
import com.yubico.yubikit.demo.raw.UsbDeviceNotFoundException
import com.yubico.yubikit.exceptions.NfcDisabledException
import com.yubico.yubikit.exceptions.NfcNotFoundException
import com.yubico.yubikit.exceptions.NoPermissionsException
import com.yubico.yubikit.transport.nfc.NfcDeviceManager

abstract class BaseYubikeyFragment(private val logTag: String) : Fragment() {
    private lateinit var tapNfcSnackBar: Snackbar
    private lateinit var enableNfcSnackBar: Snackbar
    private lateinit var permissionSnackBar: Snackbar
    protected var hasConnection = false

    abstract fun getViewModel() : YubikeyViewModel
    abstract fun onError(throwable : Throwable)
    abstract fun onUsbSession(hasPermissions: Boolean)
    abstract fun onNfcSession()

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        activity?.lifecycle?.addObserver(ActivityLifecycleObserver())

        tapNfcSnackBar = Snackbar.make(view, R.string.need_yubikey, Snackbar.LENGTH_INDEFINITE)
        permissionSnackBar = Snackbar.make(view, "Permissions are required to communicate with Usb device", Snackbar.LENGTH_INDEFINITE).setAction(R.string.request) {
            showSnackBar(permissionSnackBar, false)
            getViewModel().executeDemoCommands()
        }
        enableNfcSnackBar = Snackbar.make(view, "Please activate Nfc", Snackbar.LENGTH_LONG).setAction(R.string.enable) {
            context?.startActivity(Intent(NfcDeviceManager.NFC_SETTINGS_ACTION))
        }

        getViewModel().error.observe(viewLifecycleOwner, Observer {
            it ?: return@Observer
            when (it) {
                null -> {} // do nothing if there is no error
                is NfcNotFoundException -> Log.e(logTag, it.message ?: "NFC is not found")
                is NfcDisabledException -> showSnackBar(SnackBarType.ENABLE_NFC, true)
                is NoPermissionsException -> showSnackBar(SnackBarType.PERMISSIONS, true)
                is UsbDeviceNotFoundException -> showSnackBar(SnackBarType.TAP_NFC, !hasConnection)
                else -> {
                    hideAllSnackBars()
                    onError(it)
                }
            }
        })

        getViewModel().sessionUsb.observe(viewLifecycleOwner, Observer {
            hideAllSnackBars()
            onUsbSession(it != null && getViewModel().hasPermission(it))
        })

        getViewModel().sessionNfc.observe(viewLifecycleOwner, Observer {
            it?: return@Observer
            showSnackBar(SnackBarType.TAP_NFC, false)
            onNfcSession()
        })
    }

    override fun onStart() {
        super.onStart()
        val currentUsbSession = getViewModel().sessionUsb.value
        if (currentUsbSession!= null && getViewModel().hasPermission(currentUsbSession)) {
            onUsbSession(true)
        } else {
            showSnackBar(SnackBarType.PERMISSIONS, currentUsbSession != null)
        }
    }

    override fun onStop() {
        super.onStop()
        hideAllSnackBars()
    }

    inner class ActivityLifecycleObserver : LifecycleObserver {

        @OnLifecycleEvent(Lifecycle.Event.ON_RESUME)
        fun connectListener() {
            if (activity != null) {
                getViewModel().startNfcDiscovery(activity as Activity)
            }
        }

        @OnLifecycleEvent(Lifecycle.Event.ON_PAUSE)
        fun disconnectListener() {
            if (activity != null) {
                getViewModel().stopNfcDiscovery(activity as Activity)
            }
        }
    }

    protected fun hideAllSnackBars() {
        for (type in SnackBarType.values()) {
            showSnackBar(type, false)
        }
    }

    /**
     * Snackbar used to notify user that he needs to connect Yubikey
     */
    protected fun showSnackBar(type: SnackBarType, visible: Boolean) {
        when(type) {
            SnackBarType.PERMISSIONS -> showSnackBar(permissionSnackBar, visible)
            SnackBarType.TAP_NFC -> showSnackBar(tapNfcSnackBar, visible)
            SnackBarType.ENABLE_NFC -> showSnackBar(enableNfcSnackBar, visible)
        }
    }

    /**
     * Snackbar used to notify user that he needs to connect Yubikey
     */
    private fun showSnackBar(snackbar: Snackbar = tapNfcSnackBar, visible: Boolean) {
        if (visible) {
            snackbar.show()
        } else if (snackbar.isShown){
            snackbar.dismiss()
        }
    }

    enum class SnackBarType {
        PERMISSIONS,
        TAP_NFC,
        ENABLE_NFC
    }
}
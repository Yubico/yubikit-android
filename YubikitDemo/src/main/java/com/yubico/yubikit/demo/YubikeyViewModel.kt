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
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.ViewModel
import com.yubico.yubikit.YubiKitManager
import com.yubico.yubikit.demo.fido.arch.ErrorLiveEvent
import com.yubico.yubikit.demo.fido.arch.SingleLiveEvent
import com.yubico.yubikit.demo.raw.UsbDeviceNotFoundException
import com.yubico.yubikit.demo.settings.Ramps
import com.yubico.yubikit.exceptions.NfcDisabledException
import com.yubico.yubikit.exceptions.NfcNotFoundException
import com.yubico.yubikit.exceptions.NoPermissionsException
import com.yubico.yubikit.transport.YubiKeySession
import com.yubico.yubikit.transport.nfc.NfcConfiguration
import com.yubico.yubikit.transport.nfc.NfcSession
import com.yubico.yubikit.transport.nfc.NfcSessionListener
import com.yubico.yubikit.transport.usb.UsbConfiguration
import com.yubico.yubikit.transport.usb.UsbSession
import com.yubico.yubikit.transport.usb.UsbSessionListener
import com.yubico.yubikit.utils.ILogger
import com.yubico.yubikit.utils.Logger

private const val TAG = "YubikeyViewModel"
open class YubikeyViewModel(private val yubikitManager: YubiKitManager) : ViewModel() {

    /**
     * Keeps received UsbSessions (how many yubikeys with ccid interface were connected) and flag whether it has permissions to connect/send/receive APDU commands
     */
    private val sessions = HashMap<UsbSession, Boolean>()

    /**
     * Keeps active iso7816 session/connection that will be used to send/receive bytes on button click
     */
    private val _sessionUsb = SingleLiveEvent<UsbSession>()
    val sessionUsb: LiveData<UsbSession> = _sessionUsb

    private val _sessionNfc = SingleLiveEvent<NfcSession>()
    val sessionNfc: LiveData<NfcSession> = _sessionNfc

    private val _error = ErrorLiveEvent(TAG)
    protected fun postError(e: Throwable) {
        _error.postValue(e)
    }

    val error: LiveData<Throwable> = _error

    /**
     * Listeners for yubikey discovery (over USB and NFC)
     */
    private val usbListener = object: UsbSessionListener {
        override fun onSessionReceived(session: UsbSession, hasPermission: Boolean) {
            sessions[session] = hasPermission

            if (hasPermission) {
                // latest connection becomes active one
                _sessionUsb.value = session
            } else if (_sessionUsb.value == null) {
                // if there is no other active session use the one that has no permissions
                // otherwise we prefer to keep active session that has granted permission
                _sessionUsb.value = session
            }

            if (!hasPermission) {
                _error.value = NoPermissionsException(session.usbDevice)
            }
        }

        override fun onSessionRemoved(session: UsbSession) {
            sessions.remove(session)
            // if we have multiple sessions make sure to switch to another if we removed active one
            if (session ==_sessionUsb.value) {
                _sessionUsb.value = if(sessions.isEmpty()) null else sessions.keys.last()
            }
        }

        override fun onRequestPermissionsResult(session: UsbSession, isGranted: Boolean) {
            onSessionReceived(session, isGranted)
        }
    }

    private var nfcListener = NfcSessionListener { session ->
        // if we've got NFC tag we should execute command immediately otherwise tag will be lost
        _sessionNfc.value = session
        session.executeDemoCommands()
    }

    /**
     * Start usb discovery as soon as we create model
     */
    init {
        yubikitManager.startUsbDiscovery(UsbConfiguration(), usbListener)

        Logger.getInstance().setLogger(object : ILogger {
            override fun logDebug(message: String?) {
                Log.d(TAG, message ?: "")
            }

            override fun logError(message: String?, throwable: Throwable?) {
                Log.e(TAG, message, throwable)
            }
        })
    }

    /**
     * Stop usb discovery before model has been destoyed
     */
    override fun onCleared() {
        yubikitManager.stopUsbDiscovery()
        super.onCleared()
    }

    /**
     * Start nfc discovery when you activity in foreground
     */
    fun startNfcDiscovery(activity: Activity) {
        try {
            yubikitManager.startNfcDiscovery(
                    NfcConfiguration()
                        .setSkipNdefCheck(true)
                        .setDisableNfcDiscoverySound(Ramps.OATH_NFC_SOUND.getValue(activity) == false),
                    activity, nfcListener)
        } catch (e: NfcDisabledException) {
            _error.value = e
        } catch (e: NfcNotFoundException) {
            _error.value = e
        }
    }

    /**
     * Stop nfc discovery before your activity goes to background
     */
    fun stopNfcDiscovery(activity: Activity) {
        yubikitManager.stopNfcDiscovery(activity)
    }

    /**
     * Checks if there is usb connection and user granted permissions to connect to device
     */
    val hasConnection: Boolean
        get() {
            sessionUsb.value?.run {
                return sessions[this] == true
            } ?: run {
                return false
            }
        }


    /**
     * Handler for Run demo button
     */
    fun executeDemoCommands(session: UsbSession? = _sessionUsb.value) {
        when {
            // if user didn't accept permissions let's prompt him again
            sessions[session] == false -> yubikitManager.startUsbDiscovery(UsbConfiguration(), usbListener)
            session != null -> session.executeDemoCommands()
            else -> _error.value =
                    UsbDeviceNotFoundException("The key is not plugged in")
        }
    }

    /**
     * Execute sequence for APDU commands for specific connection
     */
    open fun YubiKeySession.executeDemoCommands() {
        // do nothing by default
    }
}
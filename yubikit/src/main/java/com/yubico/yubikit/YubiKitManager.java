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

package com.yubico.yubikit;

import android.app.Activity;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.yubico.yubikit.exceptions.NfcDisabledException;
import com.yubico.yubikit.exceptions.NfcNotFoundException;
import com.yubico.yubikit.transport.nfc.NfcConfiguration;
import com.yubico.yubikit.transport.nfc.NfcDeviceManager;
import com.yubico.yubikit.transport.nfc.NfcSession;
import com.yubico.yubikit.transport.nfc.NfcSessionListener;
import com.yubico.yubikit.transport.usb.UsbConfiguration;
import com.yubico.yubikit.transport.usb.UsbDeviceManager;
import com.yubico.yubikit.transport.usb.UsbSession;
import com.yubico.yubikit.transport.usb.UsbSessionListener;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public final class YubiKitManager {

    private final Handler handler;
    private final UsbDeviceManager usbDeviceManager;
    private final NfcDeviceManager nfcDeviceManager;

    private NfcSessionListener nfcListener;
    private UsbSessionListener usbListener;

    /**
     * Initialize instance of {@link YubiKitManager}
     * @param context application context
     */
    public YubiKitManager(Context context) {
        this(context, null);
    }

    /**
     * Initialize instance of {@link YubiKitManager}
     * @param context application context
     * @param handler on which callbacks will be invoked (default is main thread)
     */
    public YubiKitManager(Context context, @Nullable Handler handler) {
        this(handler != null ? handler : new Handler(Looper.getMainLooper()),
                new UsbDeviceManager(context.getApplicationContext()),
                new NfcDeviceManager(context.getApplicationContext()));
    }

    /**
     * Initialize instance of {@link YubiKitManager}
     * Note: this is package visible only for injection dependency within UT
     */
    YubiKitManager(@Nullable Handler handler, UsbDeviceManager usbDeviceManager, NfcDeviceManager nfcDeviceManager) {
        this.handler = handler != null ? handler : new Handler(Looper.getMainLooper());
        this.usbDeviceManager = usbDeviceManager;
        this.nfcDeviceManager = nfcDeviceManager;
    }


    /**
     * Subscribe on changes that happen via USB and detect if there any Yubikeys got connected
     *
     * This registers broadcast receivers, to unsubscribe from receiver use {@link YubiKitManager#stopUsbDiscovery()}
     * @param usbConfiguration additional configurations on how USB discovery should be handled
     * @param listener  listener that is going to be invoked upon successful discovery of key session
     *                  or failure to detect any session (lack of permissions)
     */
    public void startUsbDiscovery(final UsbConfiguration usbConfiguration, @NonNull UsbSessionListener listener) {
        usbListener = listener;
        usbDeviceManager.setListener(new UsbInternalListener());
        usbDeviceManager.enable(usbConfiguration);
    }

    /**
     * Subscribe on changes that happen via NFC and detect if there any Yubikeys tags got passed
     *
     * This registers broadcast receivers and blocks Ndef tags to be passed to activity,
     * to unsubscribe use {@link YubiKitManager#stopNfcDiscovery(Activity)}
     * @param nfcConfiguration additional configurations on how NFC discovery should be handled
     * @param listener  listener that is going to be invoked upon successful discovery of key session
     *                  or failure to detect any session (setting if off or no nfc adapter on device)
     * @param activity active (not finished) activity required for nfc foreground dispatch
     * @throws NfcDisabledException in case if NFC not activated
     * @throws NfcNotFoundException in case if NFC not available on android device
     */
    public void startNfcDiscovery(final NfcConfiguration nfcConfiguration, @NonNull Activity activity, @NonNull NfcSessionListener listener)
            throws NfcDisabledException, NfcNotFoundException {
        nfcListener = listener;
        nfcDeviceManager.setListener(new NfcInternalListener());
        nfcDeviceManager.enable(activity, nfcConfiguration);
    }

    /**
     * Unsubscribe from changes that happen via USB
     */
    public void stopUsbDiscovery() {
        usbDeviceManager.disable();
        usbListener = null;
    }

    /**
     * Unsubscribe from changes that happen via NFC
     * @param activity active (not finished) activity required for nfc foreground dispatch
     */
    public void stopNfcDiscovery(@NonNull  Activity activity) {
        nfcDeviceManager.disable(activity);
        nfcListener = null;
    }

    /**
     * Internal listeners that help to invoke callbacks on provided handler (default main thread)
     */
    private final class NfcInternalListener implements NfcSessionListener  {
        @Override
        public void onSessionReceived(@NonNull final NfcSession session) {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    if (nfcListener != null) {
                        nfcListener.onSessionReceived(session);
                    }
                }
            });
        }
    }

    private final class UsbInternalListener implements UsbSessionListener {
        @Override
        public void onSessionReceived(@NonNull final UsbSession session, final boolean hasPermissions) {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    if (usbListener != null) {
                        usbListener.onSessionReceived(session, hasPermissions);
                    }
                }
            });
        }

        @Override
        public void onSessionRemoved(@NonNull final UsbSession session) {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    if (usbListener != null) {
                        usbListener.onSessionRemoved(session);
                    }
                }
            });
        }

        @Override
        public void onRequestPermissionsResult(@NonNull final UsbSession session, final boolean isGranted) {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    if (usbListener != null) {
                        usbListener.onRequestPermissionsResult(session, isGranted);
                    }
                }
            });
        }
    }
}

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

package com.yubico.yubikit.android;

import android.app.Activity;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.yubico.yubikit.android.transport.nfc.NfcConfiguration;
import com.yubico.yubikit.android.transport.nfc.NfcDeviceManager;
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable;
import com.yubico.yubikit.android.transport.nfc.NfcSession;
import com.yubico.yubikit.android.transport.nfc.NfcSessionListener;
import com.yubico.yubikit.android.transport.usb.UsbConfiguration;
import com.yubico.yubikit.android.transport.usb.UsbDeviceManager;
import com.yubico.yubikit.android.transport.usb.UsbSession;
import com.yubico.yubikit.android.transport.usb.UsbSessionListener;

import javax.annotation.Nullable;

public final class YubiKitManager {

    private final Handler handler;
    private final UsbDeviceManager usbDeviceManager;
    @Nullable
    private final NfcDeviceManager nfcDeviceManager;

    /**
     * Initialize instance of {@link YubiKitManager}
     *
     * @param context application context
     */
    public YubiKitManager(Context context) {
        this(context, null);
    }

    @Nullable
    private static NfcDeviceManager buildNfcDeviceManager(Context context) {
        try {
            return new NfcDeviceManager(context);
        } catch (NfcNotAvailable e) {
            return null;
        }
    }

    /**
     * Initialize instance of {@link YubiKitManager}
     *
     * @param context application context
     * @param handler on which callbacks will be invoked (default is main thread)
     */
    public YubiKitManager(Context context, @Nullable Handler handler) {
        this(handler != null ? handler : new Handler(Looper.getMainLooper()),
                new UsbDeviceManager(context.getApplicationContext()),
                buildNfcDeviceManager(context.getApplicationContext()));
    }

    /**
     * Initialize instance of {@link YubiKitManager}
     *
     * @param handler          on which callbacks will be invoked (default is main thread)
     * @param usbDeviceManager UsbDeviceManager instance to use for USB communication
     * @param nfcDeviceManager NfcDeviceManager instance to use for NFC communication
     */
    public YubiKitManager(@Nullable Handler handler, UsbDeviceManager usbDeviceManager, @Nullable NfcDeviceManager nfcDeviceManager) {
        this.handler = handler != null ? handler : new Handler(Looper.getMainLooper());
        this.usbDeviceManager = usbDeviceManager;
        this.nfcDeviceManager = nfcDeviceManager;
    }


    /**
     * Subscribe on changes that happen via USB and detect if there any Yubikeys got connected
     * <p>
     * This registers broadcast receivers, to unsubscribe from receiver use {@link YubiKitManager#stopUsbDiscovery()}
     *
     * @param usbConfiguration additional configurations on how USB discovery should be handled
     * @param listener         listener that is going to be invoked upon successful discovery of key session
     *                         or failure to detect any session (lack of permissions)
     */
    public void startUsbDiscovery(final UsbConfiguration usbConfiguration, UsbSessionListener listener) {
        usbDeviceManager.enable(usbConfiguration, new UsbInternalListener(listener));
    }

    /**
     * Subscribe on changes that happen via NFC and detect if there any Yubikeys tags got passed
     * <p>
     * This registers broadcast receivers and blocks Ndef tags to be passed to activity,
     * to unsubscribe use {@link YubiKitManager#stopNfcDiscovery(Activity)}
     *
     * @param nfcConfiguration additional configurations on how NFC discovery should be handled
     * @param listener         listener that is going to be invoked upon successful discovery of key session
     *                         or failure to detect any session (setting if off or no nfc adapter on device)
     * @param activity         active (not finished) activity required for nfc foreground dispatch
     * @throws NfcNotAvailable in case if NFC not available on android device
     */
    public void startNfcDiscovery(final NfcConfiguration nfcConfiguration, Activity activity, NfcSessionListener listener)
            throws NfcNotAvailable {
        if (nfcDeviceManager == null) {
            throw new NfcNotAvailable("NFC is not available on this device", false);
        }
        nfcDeviceManager.enable(activity, nfcConfiguration, new NfcInternalListener(listener));
    }

    /**
     * Unsubscribe from changes that happen via USB
     */
    public void stopUsbDiscovery() {
        usbDeviceManager.disable();
    }

    /**
     * Unsubscribe from changes that happen via NFC
     *
     * @param activity active (not finished) activity required for nfc foreground dispatch
     */
    public void stopNfcDiscovery(Activity activity) {
        if (nfcDeviceManager != null) {
            nfcDeviceManager.disable(activity);
        }
    }

    /**
     * Internal listeners that help to invoke callbacks on provided handler (default main thread)
     */
    private final class NfcInternalListener implements NfcSessionListener {
        private final NfcSessionListener listener;

        private NfcInternalListener(NfcSessionListener listener) {
            this.listener = listener;
        }

        @Override
        public void onSessionReceived(final NfcSession session) {
            handler.post(() -> {
                listener.onSessionReceived(session);
            });
        }
    }

    private final class UsbInternalListener implements UsbSessionListener {
        private final UsbSessionListener listener;

        private UsbInternalListener(UsbSessionListener listener) {
            this.listener = listener;
        }

        @Override
        public void onSessionReceived(final UsbSession session, final boolean hasPermissions) {
            handler.post(() -> {
                listener.onSessionReceived(session, hasPermissions);
            });
        }

        @Override
        public void onSessionRemoved(final UsbSession session) {
            handler.post(() -> {
                listener.onSessionRemoved(session);
            });
        }

        @Override
        public void onRequestPermissionsResult(final UsbSession session, final boolean isGranted) {
            handler.post(() -> {
                listener.onRequestPermissionsResult(session, isGranted);
            });
        }
    }
}

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

package com.yubico.yubikit.android.transport.usb;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbManager;

import com.yubico.yubikit.core.Logger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.annotation.Nullable;

/**
 * This class allows you to access the state of USB_TRANSPORT and communicate with USB_TRANSPORT devices. Currently only host mode is supported in the public API.
 */
public class UsbDeviceManager {
    private final static String ACTION_USB_PERMISSION = "com.yubico.yubikey.USB_PERMISSION";
    private final static int YUBICO_VENDOR_ID = 0x1050;

    private final Context context;
    private final UsbManager usbManager;
    @Nullable
    private UsbBroadcastReceiver receiver;

    /**
     * Initialize instance of {@link UsbDeviceManager}
     *
     * @param context the application context
     */
    public UsbDeviceManager(Context context) {
        this.context = context;
        usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
    }

    /**
     * Registers receiver on usb connection event
     *
     * @param usbConfiguration contains information if device manager also registers receiver on permissions grant from user
     * @param listener         the UsbSessionListener to react to changes
     */
    public void enable(UsbConfiguration usbConfiguration, UsbDeviceListener listener) {
        disable();
        receiver = new UsbBroadcastReceiver(usbConfiguration, listener);
    }

    /**
     * Unregisters receiver on usb connection event
     */
    public void disable() {
        if (receiver != null) {
            receiver.stop();
            receiver = null;
        }
    }

    /**
     * Watches usb connection changes
     */
    private final class UsbBroadcastReceiver extends BroadcastReceiver {
        private final Set<android.hardware.usb.UsbDevice> pendingPermission = new HashSet<>();
        private final Map<android.hardware.usb.UsbDevice, UsbYubiKeyDevice> sessions = new HashMap<>();
        private final UsbConfiguration usbConfiguration;
        private final UsbDeviceListener listener;

        private UsbBroadcastReceiver(UsbConfiguration usbConfiguration, UsbDeviceListener listener) {
            this.usbConfiguration = usbConfiguration;
            this.listener = listener;
            IntentFilter intentFilter = new IntentFilter(UsbManager.ACTION_USB_DEVICE_ATTACHED);
            intentFilter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
            context.registerReceiver(this, intentFilter);
            checkExisting();
        }

        public void stop() {
            context.unregisterReceiver(this);
            pendingPermission.clear();
            for (UsbYubiKeyDevice session : sessions.values()) {
                listener.onDeviceRemoved(session);
            }
        }

        protected List<android.hardware.usb.UsbDevice> listDevices() {
            List<android.hardware.usb.UsbDevice> yubikeys = new ArrayList<>();
            for (android.hardware.usb.UsbDevice device : usbManager.getDeviceList().values()) {
                if (!usbConfiguration.isFilterYubicoDevices() || device.getVendorId() == YUBICO_VENDOR_ID) {
                    yubikeys.add(device);
                }
            }
            return yubikeys;
        }

        private void checkExisting() {
            for (android.hardware.usb.UsbDevice device : listDevices()) {
                checkPermissions(device);
            }
        }

        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            android.hardware.usb.UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
            if (device == null || device.getVendorId() != YUBICO_VENDOR_ID) {
                // we are not interested in devices other than yubikeys
                return;
            }

            if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {
                checkPermissions(device);
            } else if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {
                // notify user that his current session is not valid anymore
                listener.onDeviceRemoved(Objects.requireNonNull(sessions.remove(device)));
            }
        }

        private void checkPermissions(android.hardware.usb.UsbDevice device) {
            // return to user that device was discovered and whether permissions are granted or not
            UsbYubiKeyDevice session = new UsbYubiKeyDevice(usbManager, device);
            sessions.put(device, session);
            listener.onDeviceAttached(session, usbManager.hasPermission(device));

            if (!usbManager.hasPermission(device) && usbConfiguration.isHandlePermissions() && pendingPermission.add(device)) {
                Logger.d("Request permission");
                // show permissions dialog and wait for response with broadcast receiver
                PendingIntent pendingUsbPermissionIntent = PendingIntent.getBroadcast(context, 0, new Intent(ACTION_USB_PERMISSION), 0);
                context.registerReceiver(new PermissionsBroadcastReceiver(), new IntentFilter(ACTION_USB_PERMISSION));
                usbManager.requestPermission(device, pendingUsbPermissionIntent);
            }
        }

        private final class PermissionsBroadcastReceiver extends BroadcastReceiver {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (ACTION_USB_PERMISSION.equals(intent.getAction())) {
                    context.unregisterReceiver(this);
                    android.hardware.usb.UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                    if (pendingPermission.remove(device)) {
                        // device is not plugged in anymore, we're not interested in it's permissions
                        if (device == null || !listDevices().contains(device)) {
                            return;
                        }

                        listener.onRequestPermissionsResult(new UsbYubiKeyDevice(usbManager, device), usbManager.hasPermission(device));
                    }
                }
            }
        }
    }
}
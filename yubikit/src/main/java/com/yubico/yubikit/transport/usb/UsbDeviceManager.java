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

package com.yubico.yubikit.transport.usb;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;

import com.yubico.yubikit.exceptions.NoPermissionsException;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;

/**
 * This class allows you to access the state of USB_TRANSPORT and communicate with USB_TRANSPORT devices. Currently only host mode is supported in the public API.
 */
public class UsbDeviceManager {
    private final static String ACTION_USB_PERMISSION = "com.yubico.yubikey.USB_PERMISSION";
    private final static int YUBICO_VENDOR_ID = 0x1050;
    private final Context context;
    private final UsbManager usbManager;
    private boolean isPermissionRequired = false;
    private UsbBroadcastReceiver receiver;


    private transient UsbSessionListener listener = null;

    /**
     * Initialize instance of {@link UsbDeviceManager}
     * @param context the application context
     */
    public UsbDeviceManager(Context context) {
        this.context = context;
        usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
    }

    /**
     * Sets listener to Usb session discovery
     * @param listener the listener
     */
    public void setListener(final @NonNull UsbSessionListener listener) {
        this.listener = listener;
    }

    /**
     * Registers receiver on usb connection event
     * @param requirePermission if true also registers receiver on permissions grant from user
     */
    public void enable(final boolean requirePermission) {
        disable();
        isPermissionRequired = requirePermission;

        receiver = new UsbBroadcastReceiver();
        IntentFilter intentFilter = new IntentFilter(UsbManager.ACTION_USB_DEVICE_ATTACHED);
        intentFilter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
        context.registerReceiver(receiver, intentFilter);

        List<UsbDevice> devices = findDevices();
        for (UsbDevice device : devices) {
            checkPermissions(device, isPermissionRequired);
        }
    }

    /**
     * Unregisters receiver on usb connection event
     */
    public void disable() {
        if (receiver != null) {
            context.unregisterReceiver(receiver);
            receiver = null;
        }
    }

    /**
     * Checks if there are yubico device connected to device list
     * @return the object that contains property of device connected over USB
     */
    @Nullable
    private List<UsbDevice> findDevices() {
        List<UsbDevice> yubikeys = new ArrayList<>();
        for (UsbDevice device : usbManager.getDeviceList().values()) {
            if (device.getVendorId() == YUBICO_VENDOR_ID) {
                yubikeys.add(device);
            }
        }
        return yubikeys;
    }

    /**
     * Checks if user allows to use usb device and returns result via listener callbacks (device in case if permissions were granted)
     * @param device UsbDevice that will be checked for permissions
     * @param requestPermissions true if prompt user for permissions with UI dialog, otherwise returns error if no permission granted, so that app can handle permissions prompt itself
     */
    private void checkPermissions(UsbDevice device, boolean requestPermissions) {
        if (device != null) {
            // return to user that device was discovered and whether permissions are granted or not
            listener.onSessionReceived(new UsbSession(usbManager, device), usbManager.hasPermission(device));

            if (!usbManager.hasPermission(device) && requestPermissions) {
                // show permissions dialog and wait for response with broadcast receiver
                PendingIntent pendingUsbPermissionIntent = PendingIntent.getBroadcast(context, 0, new Intent(ACTION_USB_PERMISSION), 0);
                context.registerReceiver(new UsbPermissionsBroadcastReceiver(), new IntentFilter(ACTION_USB_PERMISSION));
                usbManager.requestPermission(device, pendingUsbPermissionIntent);
            }
        }
    }

    /**
     * Watches usb connection changes
     */
    private final class UsbBroadcastReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
            if (device == null || device.getVendorId() != YUBICO_VENDOR_ID) {
                // we are not interested in devices other than yubikeys
                return;
            }

            if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {
                checkPermissions(device, isPermissionRequired);
            } else if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {
                // notify user that his current session is not valid anymore
                listener.onSessionRemoved(new UsbSession(usbManager, device));
            }
        }
    }

    /**
     * Watches broadcasts from permissions dialog  (this broadcast receiver will be registered only if user passed handle permissions flag)
     */
    private final class UsbPermissionsBroadcastReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (ACTION_USB_PERMISSION.equals(action)) {
                context.unregisterReceiver(this);
                final UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                // device is not plugged in anymore, we're not interested in it's permissions
                if (device == null || !findDevices().contains(device)) {
                    return;
                }

                listener.onSessionReceived(new UsbSession(usbManager, device), usbManager.hasPermission(device));
            }
        }
    }
}

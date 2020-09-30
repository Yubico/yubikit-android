/*
 * Copyright (C) 2020 Yubico.
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

import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbInterface;
import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.YubiKeyConnection;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

abstract class UsbYubiKeyConnection implements YubiKeyConnection {
    private static final Set<UsbDevice> GLOBAL_USB_CONNECTION_LOCK = Collections.newSetFromMap(new WeakHashMap<>());

    private final UsbDevice usbDevice;
    private final UsbDeviceConnection usbDeviceConnection;
    private final UsbInterface usbInterface;

    static void releaseUsbDevice(UsbDevice usbDevice) {
        synchronized (GLOBAL_USB_CONNECTION_LOCK) {
            GLOBAL_USB_CONNECTION_LOCK.remove(usbDevice);
            GLOBAL_USB_CONNECTION_LOCK.notify();
        }
    }

    protected UsbYubiKeyConnection(UsbDevice usbDevice, UsbDeviceConnection usbDeviceConnection, UsbInterface usbInterface) throws IOException {
        synchronized (GLOBAL_USB_CONNECTION_LOCK) {
            if (!GLOBAL_USB_CONNECTION_LOCK.add(usbDevice)) {
                try {
                    GLOBAL_USB_CONNECTION_LOCK.wait(200);
                    if (!GLOBAL_USB_CONNECTION_LOCK.add(usbDevice)) {
                        throw new AlreadyInUseException(usbDevice);
                    }
                } catch (InterruptedException e) {
                    throw new IOException("Interrupted");
                }
            }
            if (!usbDeviceConnection.claimInterface(usbInterface, true)) {
                usbDeviceConnection.close();
                releaseUsbDevice(usbDevice);
                throw new IOException("Unable to claim interface");
            }
        }
        this.usbDevice = usbDevice;
        this.usbDeviceConnection = usbDeviceConnection;
        this.usbInterface = usbInterface;

        Logger.d("USB connection opened: " + this);
    }

    @Override
    public void close() {
        usbDeviceConnection.releaseInterface(usbInterface);
        usbDeviceConnection.close();
        releaseUsbDevice(usbDevice);

        Logger.d("USB connection closed: " + this);
    }
}

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

package com.yubico.yubikit.android.transport.usb.connection;

import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbInterface;

import com.yubico.yubikit.core.YubiKeyConnection;

import java.io.IOException;

import javax.annotation.Nullable;

abstract class InterfaceConnectionHandler<T extends YubiKeyConnection> implements ConnectionHandler<T> {
    private final int interfaceClass;
    private final int interfaceSubclass;

    protected InterfaceConnectionHandler(int interfaceClass, int interfaceSubclass) {
        this.interfaceClass = interfaceClass;
        this.interfaceSubclass = interfaceSubclass;
    }

    @Override
    public boolean isAvailable(UsbDevice usbDevice) {
        return getInterface(usbDevice) != null;
    }

    protected UsbInterface getClaimedInterface(UsbDevice usbDevice, UsbDeviceConnection usbDeviceConnection) throws IOException {
        UsbInterface usbInterface = getInterface(usbDevice);
        if (usbInterface != null) {
            if (!usbDeviceConnection.claimInterface(usbInterface, true)) {
                throw new IOException("Unable to claim interface");
            }
            return usbInterface;
        }
        throw new IllegalStateException("The connection type is not available via this transport");
    }

    @Nullable
    private UsbInterface getInterface(UsbDevice usbDevice) {
        for (int i = 0; i < usbDevice.getInterfaceCount(); i++) {
            UsbInterface usbInterface = usbDevice.getInterface(i);
            if (usbInterface.getInterfaceClass() == interfaceClass && usbInterface.getInterfaceSubclass() == interfaceSubclass) {
                return usbInterface;
            }
        }
        return null;
    }
}

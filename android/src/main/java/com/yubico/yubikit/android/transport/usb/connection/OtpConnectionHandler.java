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

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;

import java.io.IOException;

public class OtpConnectionHandler extends InterfaceConnectionHandler<UsbOtpConnection> {
    public OtpConnectionHandler() {
        super(UsbConstants.USB_CLASS_HID, UsbConstants.USB_INTERFACE_SUBCLASS_BOOT);
    }

    @Override
    public UsbOtpConnection createConnection(UsbDevice usbDevice, UsbDeviceConnection usbDeviceConnection) throws IOException {
        return new UsbOtpConnection(usbDeviceConnection, getClaimedInterface(usbDevice, usbDeviceConnection));
    }
}

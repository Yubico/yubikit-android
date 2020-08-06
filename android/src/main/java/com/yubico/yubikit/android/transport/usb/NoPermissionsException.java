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

import android.hardware.usb.UsbDevice;

import java.io.IOException;

/**
 * Exception that thrown when user didn't provide permissions to connect to USB device
 */
public class NoPermissionsException extends IOException {
    static final long serialVersionUID = 1L;

    public NoPermissionsException(UsbDevice usbDevice) {
        // with L+ devices we can get more verbal device name
        super("No permission granted to communicate with device " + (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP ? usbDevice.getProductName() : usbDevice.getDeviceName()));
    }
}

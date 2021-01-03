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
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.util.Pair;

import java.io.IOException;

public class SmartCardConnectionHandler extends InterfaceConnectionHandler<UsbSmartCardConnection> {
    public SmartCardConnectionHandler() {
        super(UsbConstants.USB_CLASS_CSCID, 0);
    }

    @Override
    public UsbSmartCardConnection createConnection(UsbDevice usbDevice, UsbDeviceConnection usbDeviceConnection) throws IOException {
        UsbInterface usbInterface = getClaimedInterface(usbDevice, usbDeviceConnection);
        Pair<UsbEndpoint, UsbEndpoint> endpoints = findEndpoints(usbInterface);
        return new UsbSmartCardConnection(usbDeviceConnection, usbInterface, endpoints.first, endpoints.second);
    }

    private Pair<UsbEndpoint, UsbEndpoint> findEndpoints(UsbInterface usbInterface) {
        UsbEndpoint endpointIn = null;
        UsbEndpoint endpointOut = null;

        for (int i = 0; i < usbInterface.getEndpointCount(); i++) {
            UsbEndpoint endpoint = usbInterface.getEndpoint(i);
            if (endpoint.getType() == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                if (endpoint.getDirection() == UsbConstants.USB_DIR_IN) {
                    endpointIn = endpoint;
                } else {
                    endpointOut = endpoint;
                }
            }
        }
        if (endpointIn != null && endpointOut != null) {
            return new Pair<>(endpointIn, endpointOut);
        }
        throw new IllegalStateException("Missing CCID bulk endpoints");
    }
}

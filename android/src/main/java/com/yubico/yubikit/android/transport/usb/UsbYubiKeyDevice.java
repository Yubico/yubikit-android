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

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.util.Pair;
import com.yubico.yubikit.android.transport.usb.connection.ConnectionManager;
import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;

import javax.annotation.Nullable;
import java.io.IOException;
import java.util.Objects;

public class UsbYubiKeyDevice implements YubiKeyDevice {
    private final ConnectionManager connectionManager;
    private final UsbDevice usbDevice;

    /**
     * Creates the instance of usb session to interact with the yubikey device.
     *
     * @param connectionManager manager of usb connection
     * @param usbDevice         device connected over usb that has permissions to interact with
     */
    UsbYubiKeyDevice(ConnectionManager connectionManager, UsbDevice usbDevice) {
        this.connectionManager = connectionManager;
        this.usbDevice = usbDevice;
    }

    /**
     * Returns yubikey device attached to the android device with the android device acting as the USB host.
     * It describes the capabilities of the USB device and allows to get properties/name/product id/manufacturer of device
     *
     * @return yubikey device connected over USB
     */
    public UsbDevice getUsbDevice() {
        return usbDevice;
    }

    @Override
    public Transport getTransport() {
        return Transport.USB;
    }

    @Override
    public boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType) {
        return connectionManager.supportsConnection(connectionType);
    }

    @Override
    public <T extends YubiKeyConnection> T openConnection(Class<T> connectionType) throws IOException {
        return connectionManager.openConnection(connectionType);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UsbYubiKeyDevice that = (UsbYubiKeyDevice) o;
        return Objects.equals(usbDevice, that.usbDevice);
    }

    @Override
    public int hashCode() {
        return Objects.hash(usbDevice);
    }


    /**
     * Gets bulkin and bulkout endpoints of specified interface
     *
     * @param usbInterface interface of usb device
     * @return the pair of endpoints: in and out
     */
    @Nullable
    private Pair<UsbEndpoint, UsbEndpoint> findEndpoints(UsbInterface usbInterface, int type) {
        UsbEndpoint endpointIn = null;
        UsbEndpoint endpointOut = null;

        for (int i = 0; i < usbInterface.getEndpointCount(); i++) {
            UsbEndpoint endpoint = usbInterface.getEndpoint(i);
            if (endpoint.getType() == type) {
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
        return null;
    }
}

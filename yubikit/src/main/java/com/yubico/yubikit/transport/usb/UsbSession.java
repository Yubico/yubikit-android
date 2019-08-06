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

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.util.Pair;

import androidx.annotation.NonNull;

import com.yubico.yubikit.exceptions.NoPermissionsException;
import com.yubico.yubikit.exceptions.YubikeyCommunicationException;
import com.yubico.yubikit.transport.Iso7816Connection;
import com.yubico.yubikit.transport.YubiKeySession;
import com.yubico.yubikit.utils.Logger;

import java.util.Objects;

public class UsbSession implements YubiKeySession {

    private final UsbManager usbManager;
    private final UsbDevice usbDevice;

    /**
     * Creates the instance of usb session to interact with the yubikey device.
     * @param usbManager manager of usb connection
     * @param usbDevice device connected over usb that has permissions to interact with
     */
    UsbSession(UsbManager usbManager, UsbDevice usbDevice) {
        this.usbManager = usbManager;
        this.usbDevice = usbDevice;
    }

    /**
     * Returns yubikey device attached to the android device with the android device acting as the USB host.
     * It describes the capabilities of the USB device and allows to get properties/name/product id/manufacturer of device
     * @return yubikey device connected over USB
     */
    public UsbDevice getUsbDevice() {
        return usbDevice;
    }

    @Override
    public @NonNull
    Iso7816Connection openIso7816Connection() throws YubikeyCommunicationException {
        UsbInterface ccidInterface = getInterface();
        if (ccidInterface == null) {
            throw new YubikeyCommunicationException("No CCID interface found!");
        }
        Pair<UsbEndpoint, UsbEndpoint> endpointPair = findEndpoints(ccidInterface);
        if (endpointPair.first == null || endpointPair.second == null) {
            throw new YubikeyCommunicationException("Unable to find endpoints!");
        }

        return new UsbIso7816Connection(getConnection(ccidInterface), endpointPair.first, endpointPair.second);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UsbSession that = (UsbSession) o;
        return Objects.equals(usbManager, that.usbManager) &&
                Objects.equals(usbDevice, that.usbDevice);
    }

    @Override
    public int hashCode() {
        return Objects.hash(usbManager, usbDevice);
    }

    /**
     * Sets up connection to usb device and claims ccid interface
     * @param ccidInterface ccid interface to claim
     * @return connection that is used for sending and receiving data and control messages to a USB device
     * @throws NoPermissionsException in case if user did't grant permissions for device
     * Note: it's protected for UTs to mock connection
     */
    private UsbDeviceConnection getConnection(UsbInterface ccidInterface) throws YubikeyCommunicationException {
        if (!usbManager.hasPermission(usbDevice)) {
            throw new NoPermissionsException(usbDevice);
        }
        UsbDeviceConnection connection = usbManager.openDevice(usbDevice);
        Logger.d("usb connection opened");
        if (connection == null) {
            throw new YubikeyCommunicationException("exception in UsbManager.openDevice");
        }
        connection.claimInterface(ccidInterface, true);
        return connection;
    }

    /**
     * Gets ccid interface
     * @return ccid interface of device
     */
    private UsbInterface getInterface() {
        UsbInterface ccidInterface = null;
        for (int i = 0; i < usbDevice.getInterfaceCount(); i++) {
            UsbInterface usbInterface = usbDevice.getInterface(i);
            if (usbInterface.getInterfaceClass() == UsbConstants.USB_CLASS_CSCID) {
                ccidInterface = usbInterface;
                break;
            }
        }
        return ccidInterface;
    }

    /**
     * Gets bulkin and bulkout endpoints of CCID interface
     * @param ccidInterface CCID interface
     * @return the pair of endpoints: in and out
     */
    private Pair<UsbEndpoint, UsbEndpoint> findEndpoints(UsbInterface ccidInterface) {
        UsbEndpoint endpointIn = null;
        UsbEndpoint endpointOut = null;

        for (int i = 0; i < ccidInterface.getEndpointCount(); i++) {
            UsbEndpoint endpoint = ccidInterface.getEndpoint(i);
            if (endpoint.getType() == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                if (endpoint.getDirection() == UsbConstants.USB_DIR_IN) {
                    endpointIn = endpoint;
                } else {
                    endpointOut = endpoint;
                }
            }
        }
        return new Pair<>(endpointIn, endpointOut);
    }
}

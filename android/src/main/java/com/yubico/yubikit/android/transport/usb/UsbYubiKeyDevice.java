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

import android.hardware.usb.*;
import android.util.Pair;
import com.yubico.yubikit.core.Interface;
import com.yubico.yubikit.core.NotSupportedOperation;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;

import javax.annotation.Nullable;
import java.io.IOException;
import java.util.Objects;

public class UsbYubiKeyDevice implements YubiKeyDevice {
    private final UsbManager usbManager;
    private final UsbDevice usbDevice;
    @Nullable
    private final UsbInterface ccidInterface;
    @Nullable
    private final Pair<UsbEndpoint, UsbEndpoint> ccidEndpoints;
    @Nullable
    private final UsbInterface otpInterface;


    /**
     * Creates the instance of usb session to interact with the yubikey device.
     *
     * @param usbManager manager of usb connection
     * @param usbDevice  device connected over usb that has permissions to interact with
     */
    UsbYubiKeyDevice(UsbManager usbManager, UsbDevice usbDevice) {
        this.usbManager = usbManager;
        this.usbDevice = usbDevice;

        // Check for CCID
        Pair<UsbEndpoint, UsbEndpoint> endpointPair = null;
        ccidInterface = getInterface(UsbConstants.USB_CLASS_CSCID);
        if (ccidInterface != null) {
            endpointPair = findEndpoints(ccidInterface, UsbConstants.USB_ENDPOINT_XFER_BULK);
        }
        ccidEndpoints = endpointPair;

        // Check for OTP
        UsbInterface otpInterface = getInterface(UsbConstants.USB_CLASS_HID);
        if (otpInterface != null && otpInterface.getInterfaceSubclass() == UsbConstants.USB_INTERFACE_SUBCLASS_BOOT) {
            this.otpInterface = otpInterface;
        } else {
            this.otpInterface = null;
        }
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

    /**
     * Get the UsbManager service used to interact with the YubiKey device.
     *
     * @return The Android UsbManager system service.
     */
    public UsbManager getUsbManager() {
        return usbManager;
    }

    private boolean isSmartCardAvailable() {
        return ccidInterface != null && ccidEndpoints != null;
    }

    private boolean isOtpAvailable() {
        return otpInterface != null;
    }

    @Override
    public Interface getInterface() {
        return Interface.USB;
    }

    @Override
    public boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType) {
        if (connectionType.isAssignableFrom(UsbOtpConnection.class)) {
            return isOtpAvailable();
        } else if (connectionType.isAssignableFrom(UsbSmartCardConnection.class)) {
            return isSmartCardAvailable();
        }
        return false;
    }

    @Override
    public <T extends YubiKeyConnection> T openConnection(Class<T> connectionType) throws IOException {
        if (connectionType.isAssignableFrom(UsbOtpConnection.class) && isOtpAvailable()) {
            return connectionType.cast(new UsbOtpConnection(usbDevice, openConnection(), otpInterface));
        } else if (connectionType.isAssignableFrom(UsbSmartCardConnection.class) && isSmartCardAvailable()) {
            return connectionType.cast(new UsbSmartCardConnection(usbDevice, openConnection(), ccidInterface, ccidEndpoints.first, ccidEndpoints.second));
        }
        throw new NotSupportedOperation("The connection type is not supported by this session");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UsbYubiKeyDevice that = (UsbYubiKeyDevice) o;
        return Objects.equals(usbManager, that.usbManager) &&
                Objects.equals(usbDevice, that.usbDevice);
    }

    @Override
    public int hashCode() {
        return Objects.hash(usbManager, usbDevice);
    }

    /**
     * Sets up connection to usb device and claims ccid interface
     *
     * @return connection that is used for sending and receiving data and control messages to a USB device
     * @throws NoPermissionsException in case if user did't grant permissions for device
     */
    private UsbDeviceConnection openConnection() throws IOException {
        if (!usbManager.hasPermission(usbDevice)) {
            throw new NoPermissionsException(usbDevice);
        }
        UsbDeviceConnection connection = usbManager.openDevice(usbDevice);
        if (connection == null) {
            throw new IOException("UsbManager.openDevice returned null");
        }
        return connection;
    }

    /**
     * Gets interface of a specified class
     *
     * @param usbClass UsbConstants that identifies interface class (e.g. UsbConstants.USB_CLASS_CSCID or UsbConstants.USB_CLASS_HID)
     * @return interface of device
     */
    @Nullable
    private UsbInterface getInterface(int usbClass) {
        UsbInterface selectedInterface = null;
        for (int i = 0; i < usbDevice.getInterfaceCount(); i++) {
            UsbInterface usbInterface = usbDevice.getInterface(i);
            if (usbInterface.getInterfaceClass() == usbClass) {
                selectedInterface = usbInterface;
                break;
            }
        }
        return selectedInterface;
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

package com.yubico.yubikit.android.transport.usb.connection;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.util.Pair;

import javax.annotation.Nullable;

import java.io.IOException;
import java.util.Objects;

public class FidoConnectionHandler extends InterfaceConnectionHandler<UsbFidoConnection> {
    public FidoConnectionHandler() {
        super(UsbConstants.USB_CLASS_HID, 0);
    }

    @Override
    public UsbFidoConnection createConnection(UsbDevice usbDevice, UsbDeviceConnection usbDeviceConnection) throws IOException {
        UsbInterface usbInterface = getClaimedInterface(usbDevice, usbDeviceConnection);
        Pair<UsbEndpoint, UsbEndpoint> endpoints = findEndpoints(usbInterface);
        return new UsbFidoConnection(usbDeviceConnection, usbInterface, endpoints.first, endpoints.second);
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
            if (usbInterface.getInterfaceClass() == UsbConstants.USB_CLASS_HID && usbInterface.getInterfaceSubclass() == 0) {
                return usbInterface;
            }
        }
        return null;
    }

    private static Pair<UsbEndpoint, UsbEndpoint> findEndpoints(UsbInterface usbInterface) {
        UsbEndpoint endpointIn = null;
        UsbEndpoint endpointOut = null;

        for (int i = 0; i < usbInterface.getEndpointCount(); i++) {
            UsbEndpoint endpoint = usbInterface.getEndpoint(i);
            if (endpoint.getType() == UsbConstants.USB_ENDPOINT_XFER_INT) {
                if (endpoint.getDirection() == UsbConstants.USB_DIR_IN) {
                    endpointIn = endpoint;
                } else {
                    endpointOut = endpoint;
                }
            }
        }
        return new Pair<>(Objects.requireNonNull(endpointIn), Objects.requireNonNull(endpointOut));
    }
}

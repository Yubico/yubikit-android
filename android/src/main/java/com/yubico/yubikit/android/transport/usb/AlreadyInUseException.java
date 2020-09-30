package com.yubico.yubikit.android.transport.usb;

import android.hardware.usb.UsbDevice;

import java.io.IOException;

/**
 * Exception thrown when trying to create a connection to a USB YubiKey which already has an active connection open.
 */
public class AlreadyInUseException extends IOException {
    static final long serialVersionUID = 1L;

    public AlreadyInUseException(UsbDevice usbDevice) {
        // with L+ devices we can get more verbal device name
        super("YubiKey already in use by another open connection: " + (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP ? usbDevice.getProductName() : usbDevice.getDeviceName()));
    }
}

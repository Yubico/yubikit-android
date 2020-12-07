package com.yubico.yubikit.android.transport.usb.connection;

import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;

import com.yubico.yubikit.core.YubiKeyConnection;

import java.io.IOException;
import java.util.concurrent.Semaphore;

public interface ConnectionHandler<T extends YubiKeyConnection> {
    boolean isAvailable(UsbDevice usbDevice);

    T createConnection(UsbDevice usbDevice, UsbDeviceConnection usbDeviceConnection, Semaphore connectionLock) throws IOException;
}
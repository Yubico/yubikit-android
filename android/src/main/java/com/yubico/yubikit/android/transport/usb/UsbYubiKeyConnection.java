package com.yubico.yubikit.android.transport.usb;

import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbInterface;
import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.YubiKeyConnection;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

abstract class UsbYubiKeyConnection implements YubiKeyConnection {
    private static final Set<UsbDevice> GLOBAL_USB_CONNECTION_LOCK = Collections.newSetFromMap(new WeakHashMap<>());

    private final UsbDevice usbDevice;
    private final UsbDeviceConnection usbDeviceConnection;
    private final UsbInterface usbInterface;

    static void releaseUsbDevice(UsbDevice usbDevice) {
        synchronized (GLOBAL_USB_CONNECTION_LOCK) {
            GLOBAL_USB_CONNECTION_LOCK.remove(usbDevice);
            GLOBAL_USB_CONNECTION_LOCK.notify();
        }
    }

    protected UsbYubiKeyConnection(UsbDevice usbDevice, UsbDeviceConnection usbDeviceConnection, UsbInterface usbInterface) throws IOException {
        synchronized (GLOBAL_USB_CONNECTION_LOCK) {
            if (!GLOBAL_USB_CONNECTION_LOCK.add(usbDevice)) {
                try {
                    GLOBAL_USB_CONNECTION_LOCK.wait(500);
                    if(!GLOBAL_USB_CONNECTION_LOCK.add(usbDevice)) {
                        throw new AlreadyInUseException(usbDevice);
                    }
                } catch (InterruptedException e) {
                    throw new IOException("Interrupted");
                }
            }
            if (!usbDeviceConnection.claimInterface(usbInterface, true)) {
                usbDeviceConnection.close();
                releaseUsbDevice(usbDevice);
                throw new IOException("Unable to claim interface");
            }
        }
        this.usbDevice = usbDevice;
        this.usbDeviceConnection = usbDeviceConnection;
        this.usbInterface = usbInterface;

        Logger.d("USB connection opened: " + this);
    }

    @Override
    public void close() {
        usbDeviceConnection.releaseInterface(usbInterface);
        usbDeviceConnection.close();
        releaseUsbDevice(usbDevice);

        Logger.d("USB connection closed: " + this);
    }
}

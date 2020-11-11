package com.yubico.yubikit.android;

import androidx.annotation.WorkerThread;

import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice;
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyListener;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyListener;
import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;

public abstract class YubiKeyConnectionListener<T extends YubiKeyConnection> implements UsbYubiKeyListener, NfcYubiKeyListener {
    private final Class<T> connectionType;

    protected YubiKeyConnectionListener(Class<T> connectionType) {
        this.connectionType = connectionType;
    }

    @WorkerThread
    protected void onYubiKeyDevice(YubiKeyDevice device) {
        if (device.supportsConnection(connectionType)) {
            try (T connection = device.openConnection(connectionType)) {
                onYubiKeyConnection(connection);
            } catch (Exception e) {
                onError(e);
            }
        } else {
            Logger.d("Connected YubiKey does not support desired connection type");
        }
    }

    /**
     * Called when a YubiKey supporting the desired connection type is connected.
     * <p>
     * Subclasses should override this method to react to a connected YubiKey.
     * <p>
     * NOTE: Subclasses should not close the connection, as it will be closed automatically.
     *
     * @param connection A YubiKey connection
     */
    @WorkerThread
    protected abstract void onYubiKeyConnection(T connection);

    /**
     * This method can be overriden to react to Exceptions thrown when connecting to a YubiKey.
     *
     * @param e the Exception which was thrown.
     */
    protected void onError(Exception e) {
        Logger.e("Error in YubiKey communication", e);
    }


    @Override
    public void onDeviceAttached(NfcYubiKeyDevice device) {

    }

    @Override
    public void onDeviceAttached(UsbYubiKeyDevice device, boolean hasPermission) {

    }

    @Override
    public void onDeviceRemoved(UsbYubiKeyDevice device) {

    }

    @Override
    public void onRequestPermissionsResult(UsbYubiKeyDevice device, boolean isGranted) {

    }
}

package com.yubico.yubikit.desktop;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HidDevice implements YubiKeyDevice {
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();
    private final org.hid4java.HidDevice hidDevice;
    private final int usagePage;

    HidDevice(org.hid4java.HidDevice hidDevice) {
        this.hidDevice = hidDevice;
        usagePage = hidDevice.getUsagePage() & 0xffff;
    }

    public HidOtpConnection openOtpConnection() throws IOException {
        return new HidOtpConnection(hidDevice, (byte) 0);
    }

    public HidFidoConnection openFidoConnection() throws IOException {
        if (usagePage == 0xf1d0) {
            return new HidFidoConnection(hidDevice);
        }
        throw new IOException("fido connection not supported");
    }

    @Override
    public Transport getTransport() {
        return Transport.USB;
    }

    @Override
    public boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType) {
        if (connectionType.isAssignableFrom(HidOtpConnection.class)) {
            return usagePage == 1;
        } else if (connectionType.isAssignableFrom(HidFidoConnection.class)) {
            return usagePage == 0xf1d0;
        }
        return false;
    }

    @Override
    public <T extends YubiKeyConnection> void requestConnection(Class<T> connectionType, Callback<Result<T, IOException>> callback) {
        if (!supportsConnection(connectionType)) {
            throw new IllegalStateException("Unsupported connection type");
        }
        executorService.submit(() -> {
            try {
                if (connectionType.isAssignableFrom(HidOtpConnection.class)) {
                    callback.invoke(Result.success(connectionType.cast(new HidOtpConnection(hidDevice, (byte)0))));
                } else if (connectionType.isAssignableFrom(HidFidoConnection.class)) {
                    callback.invoke(Result.success(connectionType.cast(new HidFidoConnection(hidDevice))));
                }
            } catch (IOException e) {
                callback.invoke(Result.failure(e));
            }
        });
    }
}

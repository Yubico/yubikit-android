package com.yubico.yubikit.desktop;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.otp.OtpConnection;

import org.hid4java.HidDevice;

import java.io.IOException;

public class HidOtpConnection implements OtpConnection {
    private final HidDevice hidDevice;
    private final byte interfaceId;

    HidOtpConnection(HidDevice hidDevice, byte interfaceId) throws IOException {
        if (hidDevice.isOpen()) {
            throw new IOException("Device already open");
        }
        hidDevice.open();
        this.interfaceId = interfaceId;
        this.hidDevice = hidDevice;
        Logger.d("usb connection opened");
    }

    @Override
    public void receive(byte[] report) throws IOException {
        int received = hidDevice.getFeatureReport(report, interfaceId);
        if (received != FEATURE_REPORT_SIZE) {
            throw new IOException("Unexpected amount of data read: " + received);
        }
    }

    @Override
    public void send(byte[] report) throws IOException {
        int sent = hidDevice.sendFeatureReport(report, interfaceId);
        if (sent != FEATURE_REPORT_SIZE) {
            throw new IOException("Unexpected amount of data sent: " + sent);
        }
    }

    @Override
    public void close() {
        hidDevice.close();
    }
}

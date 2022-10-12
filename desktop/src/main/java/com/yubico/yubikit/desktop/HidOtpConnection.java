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
        int offset = OperatingSystem.isWindows() ? 1 : 0;
        int reportSize = FEATURE_REPORT_SIZE + offset;

        byte[] temp = new byte[reportSize];
        int received = hidDevice.getFeatureReport(temp, interfaceId);

        System.arraycopy(temp, offset, report, 0, FEATURE_REPORT_SIZE);

        if (received != reportSize) {
            throw new IOException("Unexpected amount of data read: " + received);
        }
    }

    @Override
    public void send(byte[] report) throws IOException {
        int offset = OperatingSystem.isWindows() ? 1 : 0;
        int reportSize = FEATURE_REPORT_SIZE + offset;

        int sent = hidDevice.sendFeatureReport(report, interfaceId);
        
        if (sent != reportSize) {
            throw new IOException("Unexpected amount of data sent: " + sent);
        }
    }

    @Override
    public void close() {
        hidDevice.close();
    }
}

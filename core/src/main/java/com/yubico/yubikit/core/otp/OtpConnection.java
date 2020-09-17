package com.yubico.yubikit.core.otp;

import com.yubico.yubikit.core.YubiKeyConnection;

import java.io.IOException;

/**
 * A HID keyboard connection to a YubiKey, which uses feature reports to send and receive data.
 */
public interface OtpConnection extends YubiKeyConnection {
    int FEATURE_REPORT_SIZE = 8;

    /**
     * Writes an 8 byte feature report to the YubiKey.
     *
     * @param report the feature report data to write.
     * @throws IOException in case of a write failure
     */
    void send(byte[] report) throws IOException;

    /**
     * Read an 8 byte feature report from the YubiKey
     *
     * @param report a buffer to read into
     * @throws IOException in case of a read failure
     */
    void receive(byte[] report) throws IOException;
}

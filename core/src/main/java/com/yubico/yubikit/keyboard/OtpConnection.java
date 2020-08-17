package com.yubico.yubikit.keyboard;

import java.io.Closeable;
import java.io.IOException;

public interface OtpConnection extends Closeable {
    int readFeatureReport(byte[] report) throws IOException;
    int writeFeatureReport(byte[] report) throws IOException;
}

/*
 * Copyright (C) 2022 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.desktop.hid;

import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.otp.OtpConnection;

import com.yubico.yubikit.desktop.OperatingSystem;
import org.hid4java.HidDevice;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class HidOtpConnection implements OtpConnection {
    private final HidDevice hidDevice;
    private final byte interfaceId;

    HidOtpConnection(HidDevice hidDevice, byte interfaceId) throws IOException {
        org.slf4j.Logger logger = LoggerFactory.getLogger(HidOtpConnection.class);
        if (hidDevice.isOpen()) {
            throw new IOException("Device already open");
        }
        hidDevice.open();
        this.interfaceId = interfaceId;
        this.hidDevice = hidDevice;
        Logger.debug(logger, "usb connection opened");
    }

    @Override
    public void receive(byte[] report) throws IOException {
        int offset = OperatingSystem.isWindows() ? 1 : 0;
        int reportSize = FEATURE_REPORT_SIZE + offset;

        int received = hidDevice.getFeatureReport(report, interfaceId);

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

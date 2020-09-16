/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.android.transport.usb;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbInterface;

import com.yubico.yubikit.keyboard.OtpConnection;
import com.yubico.yubikit.utils.Logger;

import java.io.IOException;

/**
 * Class that provides interface to read and send data over YubiKey HID (keyboard) interface
 */
public class UsbOtpConnection implements OtpConnection {

    private static final int TIMEOUT = 1000;

    private final UsbDeviceConnection connection;
    private final UsbInterface hidInterface;

    private static final int TYPE_CLASS = 0x20;
    private static final int RECIPIENT_INTERFACE = 0x01;
    private static final int HID_GET_REPORT = 0x01;
    private static final int HID_SET_REPORT = 0x09;
    private static final int REPORT_TYPE_FEATURE = 0x03;

    /**
     * Sets endpoints and connection
     * Note: this method is protected to allow dependency injection for UT
     *
     * @param connection   open usb connection
     * @param hidInterface HID interface that was claimed
     *                     NOTE: controlTransfer works only with endpoint zero.
     */
    UsbOtpConnection(UsbDeviceConnection connection, UsbInterface hidInterface) {
        this.connection = connection;
        this.hidInterface = hidInterface;
        Logger.d("usb connection opened");
    }

    @Override
    public void close() {
        // NOTE: when we release HID interface YubiKey will be recognized as keyboard again,
        // it may give you a flash of UI on Android (notification how to handle Keyboard)
        // which means your active Activity may got to background for a moment
        // be aware of that and make sure that UI can handle that
        connection.releaseInterface(hidInterface);
        connection.close();
        Logger.d("usb connection closed");
    }

    @Override
    public void receive(byte[] report) throws IOException {
        int received = connection.controlTransfer(UsbConstants.USB_DIR_IN | TYPE_CLASS | RECIPIENT_INTERFACE, HID_GET_REPORT,
                REPORT_TYPE_FEATURE << 8, hidInterface.getId(), report, report.length, TIMEOUT);
        if (received != FEATURE_REPORT_SIZE) {
            throw new IOException("Unexpected amount of data read: " + received);
        }
    }

    /**
     * Write single feature report
     *
     * @param report blob size of FEATURE_RPT_SIZE
     */
    @Override
    public void send(byte[] report) throws IOException {
        int sent = connection.controlTransfer(
                UsbConstants.USB_DIR_OUT | TYPE_CLASS | RECIPIENT_INTERFACE,
                HID_SET_REPORT, REPORT_TYPE_FEATURE << 8,
                hidInterface.getId(),
                report,
                report.length,
                TIMEOUT
        );
        if (sent != FEATURE_REPORT_SIZE) {
            throw new IOException("Unexpected amount of data sent: " + sent);
        }
    }
}

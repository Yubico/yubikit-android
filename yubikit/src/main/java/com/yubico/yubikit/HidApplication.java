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

package com.yubico.yubikit;

import com.yubico.yubikit.transport.usb.NoDataException;
import com.yubico.yubikit.transport.usb.UsbHidConnection;
import com.yubico.yubikit.transport.usb.UsbSession;

import java.io.Closeable;
import java.io.IOException;

/**
 * Application that requires communication over HID Keyboard interface of YubiKey
 */
public class HidApplication implements Closeable {
    /**
     * Opens HID connection to yubikey
     */
    private UsbHidConnection connection;

    /**
     * Create new instance of {@link Iso7816Application}
     * and selects the application for use
     *
     * @param session session with YubiKey
     * @throws IOException in case of connection error
     */
    public HidApplication(UsbSession session) throws IOException {
        this.connection = session.openHidKeyboardConnection();
    }


    @Override
    public void close() throws IOException {
        connection.close();
    }

    /**
     * @return open HID connection to yubikey
     */
    public UsbHidConnection getConnection() {
        return connection;
    }


    /**
     * Receive status bytes from YubiKey
     *
     * @return status bytes (first 3 bytes are the firmware version)
     * @throws IOException
     */
    public byte[] getStatus() throws IOException {
        return connection.getStatus();
    }

    /**
     * Send data to YubiKey
     *
     * @param slot   slot that command targets
     * @param buffer data that needs to be sent
     * @return number of bytes that has been sent
     * @throws IOException
     */
    public int send(byte slot, byte[] buffer) throws IOException {
        return connection.send(slot, buffer);
    }

    /**
     * Read data from YubiKey
     *
     * @return data that received
     * @throws IOException in case of communication error or no data was received
     */
    public byte[] receive(int expectedSize) throws IOException {
        return connection.receive(expectedSize);
    }
}

/*
 * Copyright (C) 2020 Yubico.
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

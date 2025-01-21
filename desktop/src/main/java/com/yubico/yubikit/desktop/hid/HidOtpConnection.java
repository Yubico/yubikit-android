/*
 * Copyright (C) 2022-2025 Yubico.
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
import java.io.IOException;
import org.hid4java.HidDevice;
import org.slf4j.LoggerFactory;

public class HidOtpConnection implements OtpConnection {
  private final HidDevice hidDevice;
  private final byte interfaceId;
  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(HidOtpConnection.class);

  HidOtpConnection(HidDevice hidDevice, byte interfaceId) throws IOException {
    Logger.debug(logger, "Opening HID OTP connection");

    if (!hidDevice.isClosed()) {
      throw new IOException("Device already open");
    }

    if (!hidDevice.open()) {
      throw new IOException("Failure opening device");
    }

    this.interfaceId = interfaceId;
    this.hidDevice = hidDevice;
  }

  @Override
  public void receive(byte[] report) throws IOException {
    int reportSize = FEATURE_REPORT_SIZE + 1;

    int received = hidDevice.getFeatureReport(report, interfaceId);

    if (received != reportSize) {
      throw new IOException("Unexpected amount of data read: " + received);
    }
  }

  @Override
  public void send(byte[] report) throws IOException {
    int reportSize = FEATURE_REPORT_SIZE + 1;

    int sent = hidDevice.sendFeatureReport(report, interfaceId);

    if (sent != reportSize) {
      throw new IOException("Unexpected amount of data sent: " + sent);
    }
  }

  @Override
  public void close() {
    Logger.debug(logger, "Closing HID OTP connection");
    hidDevice.close();
  }
}

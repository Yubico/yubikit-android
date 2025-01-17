/*
 * Copyright (C) 2020-2025 Yubico.
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

import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.internal.Logger;
import java.io.IOException;
import org.hid4java.HidDevice;
import org.slf4j.LoggerFactory;

public class HidFidoConnection implements FidoConnection {
  private static final int TIMEOUT = 1000;

  private final HidDevice hidDevice;

  private final org.slf4j.Logger logger = LoggerFactory.getLogger(HidFidoConnection.class);

  public HidFidoConnection(HidDevice hidDevice) throws IOException {
    Logger.debug(logger, "Opening HID FIDO connection");

    if (!hidDevice.isClosed()) {
      throw new IOException("Device already open");
    }

    if (!hidDevice.open()) {
      throw new IOException("Failure opening device");
    }
    this.hidDevice = hidDevice;
  }

  @Override
  public void close() {
    Logger.debug(logger, "Closing HID FIDO connection");
    hidDevice.close();
  }

  @Override
  public void send(byte[] packet) throws IOException {
    int sent = hidDevice.write(packet, packet.length, (byte) 0);
    if (sent < 0) {
      throw new IOException(hidDevice.getLastErrorMessage());
    } else if (sent != PACKET_SIZE + 1) {
      throw new IOException("Unexpected amount of data sent: " + sent);
    }
  }

  @Override
  public void receive(byte[] packet) throws IOException {
    int received = hidDevice.read(packet, TIMEOUT);
    if (received < 0) {
      throw new IOException(hidDevice.getLastErrorMessage());
    } else if (received != PACKET_SIZE) {
      throw new IOException("Unexpected amount of data read: " + received);
    }
  }
}

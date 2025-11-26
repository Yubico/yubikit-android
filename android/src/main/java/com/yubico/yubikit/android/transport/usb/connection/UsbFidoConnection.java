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

package com.yubico.yubikit.android.transport.usb.connection;

import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import com.yubico.yubikit.core.fido.FidoConnection;
import java.io.IOException;

public class UsbFidoConnection extends UsbYubiKeyConnection implements FidoConnection {
  private static final int TIMEOUT = 3000;

  private final UsbDeviceConnection connection;
  private final UsbEndpoint bulkIn;
  private final UsbEndpoint bulkOut;

  UsbFidoConnection(
      UsbDeviceConnection connection,
      UsbInterface intf,
      UsbEndpoint endpointIn,
      UsbEndpoint endpointOut) {
    super(connection, intf);
    this.connection = connection;
    this.bulkIn = endpointIn;
    this.bulkOut = endpointOut;
  }

  @Override
  public void send(byte[] packet) throws IOException {
    int sent = connection.bulkTransfer(bulkOut, packet, packet.length, TIMEOUT);
    if (sent != FidoConnection.PACKET_SIZE) {
      throw new IOException("Failed to send full packed");
    }
  }

  @Override
  public void receive(byte[] packet) throws IOException {
    int read = connection.bulkTransfer(bulkIn, packet, packet.length, TIMEOUT);
    if (read != FidoConnection.PACKET_SIZE) {
      throw new IOException("Failed to read full packed");
    }
  }
}

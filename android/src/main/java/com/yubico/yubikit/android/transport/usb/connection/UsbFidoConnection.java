/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.android.transport.usb.connection;

import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import com.yubico.yubikit.core.fido.FidoConnection;
import java.io.IOException;

public class UsbFidoConnection extends UsbYubiKeyConnection implements FidoConnection {
  private static final int TIMEOUT = 1000;

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

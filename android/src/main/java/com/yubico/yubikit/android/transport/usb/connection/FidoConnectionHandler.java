/*
 * Copyright (C) 2023 Yubico.
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

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.util.Pair;
import java.io.IOException;
import java.util.Objects;
import javax.annotation.Nullable;

public class FidoConnectionHandler extends InterfaceConnectionHandler<UsbFidoConnection> {
  public FidoConnectionHandler() {
    super(UsbConstants.USB_CLASS_HID, 0);
  }

  @Override
  public UsbFidoConnection createConnection(
      UsbDevice usbDevice, UsbDeviceConnection usbDeviceConnection) throws IOException {
    UsbInterface usbInterface = getClaimedInterface(usbDevice, usbDeviceConnection);
    Pair<UsbEndpoint, UsbEndpoint> endpoints = findEndpoints(usbInterface);
    return new UsbFidoConnection(
        usbDeviceConnection, usbInterface, endpoints.first, endpoints.second);
  }

  protected UsbInterface getClaimedInterface(
      UsbDevice usbDevice, UsbDeviceConnection usbDeviceConnection) throws IOException {
    UsbInterface usbInterface = getInterface(usbDevice);
    if (usbInterface != null) {
      if (!usbDeviceConnection.claimInterface(usbInterface, true)) {
        throw new IOException("Unable to claim interface");
      }
      return usbInterface;
    }
    throw new IllegalStateException("The connection type is not available via this transport");
  }

  @Nullable
  private UsbInterface getInterface(UsbDevice usbDevice) {
    for (int i = 0; i < usbDevice.getInterfaceCount(); i++) {
      UsbInterface usbInterface = usbDevice.getInterface(i);
      if (usbInterface.getInterfaceClass() == UsbConstants.USB_CLASS_HID
          && usbInterface.getInterfaceSubclass() == 0) {
        return usbInterface;
      }
    }
    return null;
  }

  private static Pair<UsbEndpoint, UsbEndpoint> findEndpoints(UsbInterface usbInterface) {
    UsbEndpoint endpointIn = null;
    UsbEndpoint endpointOut = null;

    for (int i = 0; i < usbInterface.getEndpointCount(); i++) {
      UsbEndpoint endpoint = usbInterface.getEndpoint(i);
      if (endpoint.getType() == UsbConstants.USB_ENDPOINT_XFER_INT) {
        if (endpoint.getDirection() == UsbConstants.USB_DIR_IN) {
          endpointIn = endpoint;
        } else {
          endpointOut = endpoint;
        }
      }
    }
    return new Pair<>(Objects.requireNonNull(endpointIn), Objects.requireNonNull(endpointOut));
  }
}

/*
 * Copyright (C) 2023-2025 Yubico.
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
import android.hardware.usb.UsbManager;
import android.util.Pair;
import com.yubico.yubikit.android.transport.usb.NoPermissionsException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FidoConnectionHandler extends InterfaceConnectionHandler<UsbFidoConnection> {

  public FidoConnectionHandler() {
    super(UsbConstants.USB_CLASS_HID, 0);
  }

  private static final byte[] fidoUsagePage = new byte[] {0x06, (byte) 0xD0, (byte) 0xF1};
  private final Logger logger = LoggerFactory.getLogger(FidoConnectionHandler.class);
  private final Map<String, Boolean> knownSecurityKeys = new ConcurrentHashMap<>();

  private @Nullable UsbInterface getFidoInterface(UsbDevice device) {
    int interfaceCount = device.getInterfaceCount();
    for (int i = 0; i < interfaceCount; i++) {
      UsbInterface usbInterface = device.getInterface(i);
      if (usbInterface.getInterfaceClass() == UsbConstants.USB_CLASS_HID
          && usbInterface.getInterfaceSubclass() == 0) {
        return usbInterface;
      }
    }
    logger.debug("Failed to get FIDO interface");
    return null;
  }

  private boolean hasFidoUsagePage(UsbManager manager, UsbDevice usbDevice) {
    final int RECIPIENT_INTERFACE = 0x01;
    final int HID_GET_DESCRIPTOR = 0x06;
    final int HID_DESCRIPTOR_TYPE = 0x22; // Report
    final int HID_DESCRIPTOR_INDEX = 0x00;

    final int TIMEOUT_MS = 1000;

    UsbDeviceConnection connection = null;
    UsbInterface fidoInterface = getFidoInterface(usbDevice);
    if (fidoInterface == null) {
      return false;
    }

    try {
      if (!manager.hasPermission(usbDevice)) {
        throw new NoPermissionsException(usbDevice);
      }

      connection = manager.openDevice(usbDevice);
      if (!connection.claimInterface(fidoInterface, true)) {
        logger.debug("Failed to claim FIDO interface");
        return false;
      }

      byte[] buffer = new byte[3];
      int readLen =
          connection.controlTransfer(
              UsbConstants.USB_DIR_IN | UsbConstants.USB_TYPE_STANDARD | RECIPIENT_INTERFACE,
              HID_GET_DESCRIPTOR,
              (HID_DESCRIPTOR_TYPE << 8) | HID_DESCRIPTOR_INDEX, // wValue
              fidoInterface.getId(), // wIndex
              buffer,
              buffer.length,
              TIMEOUT_MS);

      if (readLen != 3) {
        logger.debug("Failed to read HID report");
        return false;
      }
      return Arrays.equals(buffer, fidoUsagePage);

    } catch (Exception e) {
      logger.error("Exception during reading HID report: ", e);
      return false;
    } finally {
      if (connection != null) {
        if (!connection.releaseInterface(fidoInterface)) {
          logger.warn("Failed to release FIDO interface");
        }
        connection.close();
      }
    }
  }

  private boolean isFidoDevice(UsbManager manager, UsbDevice usbDevice) {
    Boolean isFidoDevice = knownSecurityKeys.get(usbDevice.getDeviceName());
    if (isFidoDevice != null) {
      return isFidoDevice;
    }

    boolean hasFidoUsagePage = hasFidoUsagePage(manager, usbDevice);
    knownSecurityKeys.put(usbDevice.getDeviceName(), hasFidoUsagePage);
    return hasFidoUsagePage;
  }

  @Override
  public boolean isAvailable(UsbManager manager, UsbDevice usbDevice) {
    if (!super.isAvailable(manager, usbDevice)) {
      return false;
    }

    return isFidoDevice(manager, usbDevice);
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

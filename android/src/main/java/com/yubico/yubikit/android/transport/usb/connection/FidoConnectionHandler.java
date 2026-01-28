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
import android.util.Pair;
import java.io.IOException;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FidoConnectionHandler extends InterfaceConnectionHandler<UsbFidoConnection> {

  static final int USB_RECIPIENT_INTERFACE = 0x01;
  static final int HID_GET_DESCRIPTOR = 0x06;
  static final int HID_DESCRIPTOR_TYPE = 0x21;
  static final int HID_DESCRIPTOR_TYPE_REPORT = 0x22;
  static final int HID_DESCRIPTOR_INDEX = 0x00;
  static final int TIMEOUT_MS = 1000;
  static final int DEFAULT_REPORT_DESC_SIZE = 256;
  static final int HID_DESCRIPTOR_SIZE = 9;

  private final Logger logger = LoggerFactory.getLogger(FidoConnectionHandler.class);

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

  /** Find the HID interface with the FIDO usage page (0xF1D0) and claim it. */
  protected UsbInterface getClaimedInterface(UsbDevice device, UsbDeviceConnection connection)
      throws IOException {
    for (int i = 0; i < device.getInterfaceCount(); i++) {
      UsbInterface usbInterface = device.getInterface(i);
      int interfaceId = usbInterface.getId();

      if (usbInterface.getInterfaceClass() != UsbConstants.USB_CLASS_HID) {
        logger.debug(
            "Failed to interface {} on {} is not HID",
            usbInterface.getId(),
            device.getDeviceName());
        continue;
      }

      if (!connection.claimInterface(usbInterface, true)) {
        logger.debug(
            "Failed to claim interface {} on {} has not FIDO usage page",
            usbInterface.getId(),
            device.getDeviceName());
        continue;
      }

      boolean isFido = false;
      try {
        int reportDescLength = DEFAULT_REPORT_DESC_SIZE;
        try {
          reportDescLength = getReportDescriptorLength(connection, interfaceId);
        } catch (Exception ignore) {
          logger.debug(
              "Failed to get HID Report Descriptor length, using default buffer size {}",
              DEFAULT_REPORT_DESC_SIZE);
        }
        byte[] reportDescriptor = readReportDescriptor(connection, interfaceId, reportDescLength);
        isFido = hasFidoUsagePage(reportDescriptor);

        if (isFido) {
          // Found! Return while leaving claimed
          return usbInterface;
        }
        logger.debug(
            "Interface {} on {} has not FIDO usage page",
            usbInterface.getId(),
            device.getDeviceName());
      } finally {
        if (!isFido) {
          // only release this interface if we are not returning it
          connection.releaseInterface(usbInterface);
        }
      }
    }
    throw new IllegalStateException("No HID interface with FIDO usage page found");
  }

  /** Checks if a given report descriptor contains the FIDO usage page tag. */
  private static boolean hasFidoUsagePage(byte[] reportDescriptor) {
    if (reportDescriptor.length < 3) return false;
    for (int i = 0; i < reportDescriptor.length - 2; i++) {
      if ((reportDescriptor[i] & 0xFF) == 0x06
          && (reportDescriptor[i + 1] & 0xFF) == 0xD0
          && (reportDescriptor[i + 2] & 0xFF) == 0xF1) {
        return true;
      }
    }
    return false;
  }

  /** Finds IN and OUT interrupt endpoints for the given HID interface. */
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

  private static byte[] readReportDescriptor(
      UsbDeviceConnection connection, int interfaceId, int reportDescLength) throws IOException {
    byte[] buffer = new byte[reportDescLength];
    int readLen =
        hidControlTransfer(
            connection, HID_DESCRIPTOR_TYPE_REPORT, interfaceId, buffer, buffer.length);

    if (readLen == -1) {
      throw new IOException("Failed to read report descriptor");
    }

    if (readLen == 0) {
      throw new IOException("Received empty report descriptor");
    }

    return (readLen < buffer.length) ? java.util.Arrays.copyOf(buffer, readLen) : buffer;
  }

  public static int getReportDescriptorLength(UsbDeviceConnection connection, int interfaceId) {
    byte[] hidDescriptorBuffer = new byte[HID_DESCRIPTOR_SIZE];
    int readLen =
        hidControlTransfer(
            connection,
            HID_DESCRIPTOR_TYPE,
            interfaceId,
            hidDescriptorBuffer,
            hidDescriptorBuffer.length);

    if (readLen != HID_DESCRIPTOR_SIZE) {
      throw new IllegalStateException("Unable to read HID descriptor");
    }

    return ((hidDescriptorBuffer[8] & 0xFF) << 8) | (hidDescriptorBuffer[7] & 0xFF);
  }

  /** Performs a HID class control transfer and returns the length of data read. */
  private static int hidControlTransfer(
      UsbDeviceConnection connection,
      int descriptorType,
      int interfaceId,
      byte[] buffer,
      int bufferLength) {
    int wValue = (descriptorType << 8) | HID_DESCRIPTOR_INDEX;
    return connection.controlTransfer(
        UsbConstants.USB_DIR_IN | UsbConstants.USB_TYPE_STANDARD | USB_RECIPIENT_INTERFACE,
        HID_GET_DESCRIPTOR,
        wValue,
        interfaceId,
        buffer,
        bufferLength,
        TIMEOUT_MS);
  }
}

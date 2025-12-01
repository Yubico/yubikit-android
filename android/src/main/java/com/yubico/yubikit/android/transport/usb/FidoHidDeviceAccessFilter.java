/*
 * Copyright (C) 2025 Yubico.
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
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import java.util.Arrays;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FidoHidDeviceAccessFilter implements DeviceAccessFilter {
  private static final byte[] fidoUsagePage = new byte[] {0x06, (byte) 0xD0, (byte) 0xF1};
  private final Logger logger = LoggerFactory.getLogger(FidoHidDeviceAccessFilter.class);

  /**
   * Returns a VendorProductFilter that matches all vendor and product IDs.
   *
   * @return a VendorProductFilter accepting any vendor/product combination
   */
  @Override
  public VendorProductFilter getVendorProductFilter() {
    // match all vendors
    return (vendorId, productId) -> true;
  }

  /**
   * Determines if the specified USB device supports the FIDO HID usage page.
   *
   * @param manager the UsbManager instance
   * @param usbDevice the UsbDevice to check
   * @return true if the device matches FIDO HID criteria, false otherwise
   */
  @Override
  public boolean matches(UsbManager manager, UsbDevice usbDevice) {
    return isFidoDevice(manager, usbDevice);
  }

  private boolean isFidoDevice(UsbManager manager, UsbDevice usbDevice) {
    return hasFidoUsagePage(manager, usbDevice);
  }

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
}

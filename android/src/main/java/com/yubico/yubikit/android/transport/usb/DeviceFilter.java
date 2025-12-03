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

import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;

/** Provides methods to filter USB devices based on vendor/product IDs and device properties. */
public class DeviceFilter {
  /**
   * Checks if the given vendor and product IDs match the filter criteria.
   *
   * @param vendorId the USB vendor ID
   * @param productId the USB product ID
   * @return true if the IDs match the filter, false otherwise
   */
  boolean checkVendorProductIds(int vendorId, int productId) {
    return true;
  }

  /**
   * Evaluates whether the specified USB device is permitted for use by the SDK. This method may
   * perform tests or checks on the device and returns true if the device meets all criteria
   * required for SDK usage.
   *
   * @param usbManager the UsbManager instance
   * @param usbDevice the UsbDevice to evaluate
   * @return true if the device is allowed for SDK use, false otherwise
   */
  boolean checkUsbDevice(UsbManager usbManager, UsbDevice usbDevice) {
    return true;
  }
}

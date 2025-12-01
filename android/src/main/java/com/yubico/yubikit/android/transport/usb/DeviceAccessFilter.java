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

/**
 * Interface for filtering USB devices based on access criteria. Implementations can define custom
 * logic to determine if a device should be accessible.
 */
public interface DeviceAccessFilter {
  /**
   * Returns the associated VendorProductFilter for vendor/product ID matching.
   *
   * @return the VendorProductFilter used by this filter
   */
  VendorProductFilter getVendorProductFilter();

  /**
   * Determines whether the specified USB device matches the access criteria.
   *
   * @param manager the UsbManager instance
   * @param device the UsbDevice to check
   * @return true if the device matches the filter, false otherwise
   */
  boolean matches(UsbManager manager, UsbDevice device);
}

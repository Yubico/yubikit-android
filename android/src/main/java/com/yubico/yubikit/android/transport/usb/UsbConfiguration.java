/*
 * Copyright (C) 2020-2022 Yubico.
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
import org.jspecify.annotations.Nullable;

/** Additional configurations for USB discovery management */
public class UsbConfiguration {

  static final VendorProductFilter DEFAULT_VENDOR_PRODUCT_FILTER =
      (vendorId, productId) -> vendorId == UsbYubiKeyDevice.YUBICO_VENDOR_ID;

  static final DeviceAccessFilter DEFAULT_DEVICE_ACCESS_FILTER =
      new DeviceAccessFilter() {
        @Override
        public VendorProductFilter getVendorProductFilter() {
          return DEFAULT_VENDOR_PRODUCT_FILTER;
        }

        @Override
        public boolean matches(UsbManager manager, UsbDevice device) {
          return true;
        }
      };

  // whether to prompt permissions when application needs them
  private boolean handlePermissions = true;

  // filter for usb devices
  private @Nullable DeviceAccessFilter deviceAccessFilter;

  boolean isHandlePermissions() {
    return handlePermissions;
  }

  /**
   * Returns the configured VendorProductFilter, or the default if none is set.
   *
   * @return the VendorProductFilter in use
   */
  VendorProductFilter getVendorProductFilter() {
    if (deviceAccessFilter != null) {
      return deviceAccessFilter.getVendorProductFilter();
    }
    return DEFAULT_VENDOR_PRODUCT_FILTER;
  }

  /**
   * Returns the configured DeviceAccessFilter, or the default if none is set.
   *
   * @return the DeviceAccessFilter in use
   */
  DeviceAccessFilter getDeviceAccessFilter() {
    if (deviceAccessFilter != null) {
      return deviceAccessFilter;
    }

    return DEFAULT_DEVICE_ACCESS_FILTER;
  }

  /**
   * Set YubiKitManager to show dialog for permissions on USB connection
   *
   * @param handlePermissions true to show dialog for permissions otherwise it's delegated on user
   *     to make sure that application has permissions to communicate with device
   * @return the UsbConfiguration, for chaining
   */
  public UsbConfiguration handlePermissions(boolean handlePermissions) {
    this.handlePermissions = handlePermissions;
    return this;
  }

  /**
   * Sets a VendorProductFilter for USB device selection.
   *
   * @param vendorProductFilter the VendorProductFilter to use
   * @return this UsbConfiguration instance for chaining
   */
  public UsbConfiguration setVendorProductFilter(VendorProductFilter vendorProductFilter) {
    this.deviceAccessFilter =
        new DeviceAccessFilter() {
          @Override
          public VendorProductFilter getVendorProductFilter() {
            return vendorProductFilter;
          }

          @Override
          public boolean matches(UsbManager manager, UsbDevice device) {
            return true;
          }
        };
    return this;
  }

  /**
   * Sets a DeviceAccessFilter for USB device selection.
   *
   * @param deviceAccessFilter the DeviceAccessFilter to use
   * @return this UsbConfiguration instance for chaining
   */
  public UsbConfiguration setDeviceAccessFilter(DeviceAccessFilter deviceAccessFilter) {
    this.deviceAccessFilter = deviceAccessFilter;
    return this;
  }
}

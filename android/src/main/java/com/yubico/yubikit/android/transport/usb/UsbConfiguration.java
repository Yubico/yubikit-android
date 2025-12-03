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

/** Additional configurations for USB discovery management */
public class UsbConfiguration {
  // whether to prompt permissions when application needs them
  private boolean handlePermissions = true;

  // default filter
  private DeviceFilter deviceFilter = YUBICO_VENDOR_FILTER;

  boolean isHandlePermissions() {
    return handlePermissions;
  }

  DeviceFilter getDeviceFilter() {
    return deviceFilter;
  }

  public UsbConfiguration() {}

  public UsbConfiguration(UsbConfiguration other) {
    this.handlePermissions = other.handlePermissions;
    this.deviceFilter = other.deviceFilter;
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

  public UsbConfiguration setDeviceFilter(DeviceFilter deviceFilter) {
    this.deviceFilter = deviceFilter;
    return this;
  }

  public static final YubicoVendorFilter YUBICO_VENDOR_FILTER = new YubicoVendorFilter();

  public static class YubicoVendorFilter extends DeviceFilter {
    @Override
    boolean checkVendorProductIds(int vendorId, int productId) {
      return vendorId == UsbYubiKeyDevice.YUBICO_VENDOR_ID;
    }
  }
}

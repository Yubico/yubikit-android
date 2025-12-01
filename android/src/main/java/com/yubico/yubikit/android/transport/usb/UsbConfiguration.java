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

  static final UsbDeviceFilter DEFAULT_USB_DEVICE_FILTER =
      (vendorId, productId) -> vendorId == UsbYubiKeyDevice.YUBICO_VENDOR_ID;

  static final UsbManagerFilter DEFAULT_USB_MANAGER_FILTER =
      new UsbManagerFilter() {
        @Override
        public UsbDeviceFilter getDeviceFilter() {
          return DEFAULT_USB_DEVICE_FILTER;
        }

        @Override
        public boolean matches(UsbManager manager, UsbDevice device) {
          return true;
        }
      };

  // whether to prompt permissions when application needs them
  private boolean handlePermissions = true;

  // filter for usb devices
  private @Nullable UsbManagerFilter deviceFilter;

  boolean isHandlePermissions() {
    return handlePermissions;
  }

  UsbDeviceFilter getUsbDeviceFilter() {
    if (deviceFilter != null) {
      return deviceFilter.getDeviceFilter();
    }
    return DEFAULT_USB_DEVICE_FILTER;
  }

  UsbManagerFilter getUsbManagerFilter() {
    if (deviceFilter != null) {
      return deviceFilter;
    }

    return DEFAULT_USB_MANAGER_FILTER;
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

  public UsbConfiguration deviceFilter(UsbDeviceFilter usbDeviceFilter) {
    this.deviceFilter =
        new UsbManagerFilter() {
          @Override
          public UsbDeviceFilter getDeviceFilter() {
            return usbDeviceFilter;
          }

          @Override
          public boolean matches(UsbManager manager, UsbDevice device) {
            return true;
          }
        };
    return this;
  }

  public UsbConfiguration deviceFilter(UsbManagerFilter usbManagerFilter) {
    this.deviceFilter = usbManagerFilter;
    return this;
  }
}

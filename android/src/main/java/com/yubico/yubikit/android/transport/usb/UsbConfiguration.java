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

  public static final UsbDeviceFilter DEFAULT_USB_DEVICE_FILTER =
      (vendorId, productId) -> vendorId == UsbYubiKeyDevice.YUBICO_VENDOR_ID;

  public static final UsbManagerFilter DEFAULT_USB_MANAGER_FILTER =
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
  private UsbDeviceFilter usbDeviceFilter = DEFAULT_USB_DEVICE_FILTER;

  // filter for usb devices
  private UsbManagerFilter usbManagerFilter = DEFAULT_USB_MANAGER_FILTER;

  // filter for usb devices
  private @Nullable UsbDeviceFilter usbDeviceFilterAlt;

  // filter for usb devices
  private @Nullable UsbManagerFilter usbManagerFilterAlt;

  // filter for usb devices
  private @Nullable UsbManagerFilter deviceFilter;

  boolean isHandlePermissions() {
    return handlePermissions;
  }

  // first variant - 2 variables
  UsbDeviceFilter usbDeviceFilter() {
    return usbDeviceFilter;
  }

  UsbManagerFilter usbManagerFilter() {
    return usbManagerFilter;
  }

  // first variant - 2 variables
  UsbDeviceFilter usbDeviceFilterAlt() {
    if (usbManagerFilterAlt != null) {
      return usbManagerFilterAlt.getDeviceFilter();
    }
    if (usbDeviceFilterAlt != null) {
      return usbDeviceFilterAlt;
    }
    return DEFAULT_USB_DEVICE_FILTER;
  }

  UsbManagerFilter getUsbManagerFilterAlt() {
    if (usbManagerFilterAlt != null) {
      return usbManagerFilterAlt;
    }
    return DEFAULT_USB_MANAGER_FILTER;
  }

  // third variant - 1 variable
  UsbDeviceFilter usbDeviceFilterAlt2() {
    if (deviceFilter != null) {
      return deviceFilter.getDeviceFilter();
    }
    return DEFAULT_USB_DEVICE_FILTER;
  }

  UsbManagerFilter getUsbManagerFilterAlt2() {
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

  public UsbConfiguration usbDeviceFilter(UsbDeviceFilter usbDeviceFilter) {
    this.usbDeviceFilter = usbDeviceFilter;
    return this;
  }

  public UsbConfiguration usbManagerFilter(UsbManagerFilter usbManagerFilter) {
    this.usbManagerFilter = usbManagerFilter;
    return this;
  }

  public UsbConfiguration deviceFilterAlt1(UsbDeviceFilter usbDeviceFilter) {
    this.usbDeviceFilterAlt = usbDeviceFilter;
    this.usbManagerFilterAlt =
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

  public UsbConfiguration deviceFilterAlt1(UsbManagerFilter usbManagerFilter) {
    this.usbManagerFilterAlt = usbManagerFilter;
    this.usbDeviceFilterAlt = usbManagerFilter.getDeviceFilter();
    return this;
  }

  public UsbConfiguration deviceFilterAlt2(UsbDeviceFilter usbDeviceFilter) {
    this.usbManagerFilterAlt =
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

  public UsbConfiguration deviceFilterAlt2(UsbManagerFilter usbManagerFilter) {
    this.deviceFilter = usbManagerFilter;
    return this;
  }
}

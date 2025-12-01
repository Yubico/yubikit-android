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

  public static final UsbDeviceFilter DEFAULT_USB_DEVICE_FILTER =
      (vendorId, productId) -> vendorId == UsbYubiKeyDevice.YUBICO_VENDOR_ID;

  public static final UsbManagerFilter DEFAULT_USB_MANAGER_FILTER = (manager, device) -> true;

  // whether to prompt permissions when application needs them
  private boolean handlePermissions = true;

  // filter for usb devices
  private UsbDeviceFilter usbDeviceFilter = DEFAULT_USB_DEVICE_FILTER;

  // filter for usb devices
  private UsbManagerFilter usbManagerFilter = DEFAULT_USB_MANAGER_FILTER;

  boolean isHandlePermissions() {
    return handlePermissions;
  }

  UsbDeviceFilter usbDeviceFilter() {
    return usbDeviceFilter;
  }

  UsbManagerFilter usbManagerFilter() {
    return usbManagerFilter;
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
}

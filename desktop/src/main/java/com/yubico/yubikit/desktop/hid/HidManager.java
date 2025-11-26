/*
 * Copyright (C) 2022-2025 Yubico.
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
package com.yubico.yubikit.desktop.hid;

import com.yubico.yubikit.core.YubiKeyDevice;
import java.util.List;
import java.util.stream.Collectors;
import org.hid4java.HidServices;
import org.jspecify.annotations.Nullable;

public class HidManager {

  private static final int HID_USAGE_PAGE_OTP = 0x0001;
  private static final int HID_USAGE_PAGE_FIDO = 0xf1d0;

  private final HidServices services;

  public HidManager() {
    this(org.hid4java.HidManager.getHidServices());
  }

  HidManager(HidServices services) {
    this.services = services;
  }

  public List<HidDevice> getHidDevices(int vendorId, @Nullable Integer usagePage) {
    return services.getAttachedHidDevices().stream()
        .filter(
            d -> d.getVendorId() == vendorId && (usagePage != null && getUsagePage(d) == usagePage))
        .map(HidDevice::new)
        .collect(Collectors.toList());
  }

  public List<HidDevice> getOtpDevices() {
    return getHidDevices(YubiKeyDevice.YUBICO_VENDOR_ID, HID_USAGE_PAGE_OTP);
  }

  public List<HidDevice> getFidoDevices() {
    return services.getAttachedHidDevices().stream()
        .filter(d -> getUsagePage(d) == HID_USAGE_PAGE_FIDO)
        .map(HidDevice::new)
        .collect(Collectors.toList());
  }

  private int getUsagePage(org.hid4java.HidDevice device) {
    return device.getUsagePage() & 0xffff;
  }
}

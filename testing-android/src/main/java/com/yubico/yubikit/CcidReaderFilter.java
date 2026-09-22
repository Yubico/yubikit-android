/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import com.yubico.yubikit.android.transport.usb.DeviceFilter;
import com.yubico.yubikit.core.YubiKeyDevice;

/**
 * Admits YubiKeys plus any third-party USB smart card reader.
 *
 * <p>The SDK's default filter matches the Yubico vendor id, so a reader such as the HID OMNIKEY
 * 5022-CL or the Identiv SCR3500 C is never enumerated and no test can reach the reader-specific
 * code paths in {@code UsbSmartCardConnection} (CCID response chaining, T=1 framing). Everything
 * below the filter is already vendor-agnostic - {@code SmartCardConnectionHandler} matches on USB
 * class {@code CSCID} - so widening the filter is all that is needed.
 *
 * <p>The id-only gate runs before the system permission prompt, so it looks the device up in the
 * attached-device list to check for a CCID interface. Matching on the ids alone would prompt for
 * every peripheral on the bus and leave a modal dialog sitting on top of a hardware test run.
 */
public class CcidReaderFilter extends DeviceFilter {

  private final UsbManager usbManager;

  public CcidReaderFilter(UsbManager usbManager) {
    this.usbManager = usbManager;
  }

  @Override
  public boolean checkVendorProductIds(int vendorId, int productId) {
    if (vendorId == YubiKeyDevice.YUBICO_VENDOR_ID) {
      return true;
    }
    for (UsbDevice usbDevice : usbManager.getDeviceList().values()) {
      if (usbDevice.getVendorId() == vendorId
          && usbDevice.getProductId() == productId
          && hasCcidInterface(usbDevice)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public boolean checkUsbDevice(UsbManager usbManager, UsbDevice usbDevice) {
    // A YubiKey in a non-CCID mode has no CCID interface, so keep admitting
    // Yubico devices unconditionally - the FIDO and OTP suites need them.
    return usbDevice.getVendorId() == YubiKeyDevice.YUBICO_VENDOR_ID || hasCcidInterface(usbDevice);
  }

  private static boolean hasCcidInterface(UsbDevice usbDevice) {
    for (int i = 0; i < usbDevice.getInterfaceCount(); i++) {
      if (usbDevice.getInterface(i).getInterfaceClass() == UsbConstants.USB_CLASS_CSCID) {
        return true;
      }
    }
    return false;
  }
}

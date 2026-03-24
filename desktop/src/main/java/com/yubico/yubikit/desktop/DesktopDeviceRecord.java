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
package com.yubico.yubikit.desktop;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.management.DeviceInfo;

/**
 * A record combining a {@link YubiKeyDevice}, its {@link DeviceInfo}, and a {@link
 * DesktopDeviceSelector} that can be used to target this specific device for connection operations.
 *
 * <p>The selector is automatically derived:
 *
 * <ul>
 *   <li>If the device has both a serial number and a fingerprint, the selector contains both,
 *       allowing lookup by either identifier.
 *   <li>If only a serial number is available, the selector is serial-based.
 *   <li>If only a fingerprint is available (e.g. devices that do not expose a serial number), the
 *       selector is fingerprint-based (available from {@link UsbYubiKeyDevice#getFingerprint()},
 *       {@link CompositeDevice#getFingerprint()}, or {@link NfcYubiKeyDevice#getFingerprint()}).
 * </ul>
 *
 * <p><b>Usage example:</b>
 *
 * <pre>{@code
 * YubiKitManager mgr = new YubiKitManager();
 * List<DesktopDeviceRecord> devices = mgr.listDeviceRecords();
 *
 * // Select a specific device
 * DesktopDeviceSelector sel = devices.get(0).getSelector();
 * try (SmartCardConnection c = mgr.openConnection(sel, SmartCardConnection.class)) {
 *     // run operation on the selected device
 * }
 * }</pre>
 *
 * @see YubiKitManager#listDeviceRecords()
 * @see DesktopDeviceSelector
 */
public final class DesktopDeviceRecord {

  private final YubiKeyDevice device;
  private final DeviceInfo info;
  private final DesktopDeviceSelector selector;

  /**
   * Creates a new record for the given device, info, and selector.
   *
   * @param device the YubiKey device
   * @param info the device info
   * @param selector the selector for targeting this device
   */
  public DesktopDeviceRecord(
      YubiKeyDevice device, DeviceInfo info, DesktopDeviceSelector selector) {
    this.device = device;
    this.info = info;
    this.selector = selector;
  }

  /** Returns the YubiKey device reference. */
  public YubiKeyDevice getDevice() {
    return device;
  }

  /** Returns the device information (serial, version, capabilities, etc.). */
  public DeviceInfo getInfo() {
    return info;
  }

  /**
   * Returns the selector that uniquely identifies this device. Use this to open a connection on
   * this specific device via {@link YubiKitManager#openConnection(DesktopDeviceSelector, Class)}.
   */
  public DesktopDeviceSelector getSelector() {
    return selector;
  }

  @Override
  public String toString() {
    return "DesktopDeviceRecord{"
        + "selector="
        + selector
        + ", serial="
        + info.getSerialNumber()
        + ", version="
        + info.getVersion()
        + "}";
  }
}

/*
 * Copyright (C) 2022-2026 Yubico.
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

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.desktop.DesktopDeviceRecord;
import com.yubico.yubikit.desktop.DesktopDeviceSelector;
import com.yubico.yubikit.desktop.OperatingSystem;
import com.yubico.yubikit.desktop.YubiKitManager;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DesktopTestDriver {

  private final YubiKitManager yubikit;

  private static final Logger logger = LoggerFactory.getLogger(DesktopTestDriver.class);

  /**
   * System property to specify a YubiKey device for testing. Accepts either a serial number (e.g.
   * {@code -Dyubikit.testdevice=123456}) or a fingerprint (e.g. {@code
   * -Dyubikit.testdevice=DevSrvsID:4294988713}) to target a specific device when multiple YubiKeys
   * are connected.
   */
  public static final String DEVICE_PROPERTY = "yubikit.testdevice";

  public DesktopTestDriver() {
    if (OperatingSystem.isMac()) {
      System.setProperty(
          "sun.security.smartcardio.library",
          "/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC");
    }
    yubikit = new YubiKitManager();
  }

  /**
   * Returns a YubiKey device for testing.
   *
   * <p>Device selection behavior:
   *
   * <ul>
   *   <li>If the system property {@value #DEVICE_PROPERTY} is set, selects the device by serial
   *       number (if the value is an integer) or by fingerprint (otherwise).
   *   <li>If exactly one device is connected, uses that device.
   *   <li>If multiple devices are connected and no serial is specified, throws {@link
   *       IllegalStateException} with instructions to set the system property.
   * </ul>
   *
   * @return the selected YubiKey device
   * @throws InterruptedException if interrupted while waiting
   */
  public YubiKeyDevice awaitSession() throws InterruptedException {
    String deviceProperty = System.getProperty(DEVICE_PROPERTY);
    if (deviceProperty != null) {
      DesktopDeviceSelector selector;
      try {
        int serial = Integer.parseInt(deviceProperty);
        logger.info("Selecting device by serial number: {}", serial);
        selector = DesktopDeviceSelector.forSerial(serial);
      } catch (NumberFormatException e) {
        // Not a number — treat as fingerprint
        logger.info("Selecting device by fingerprint: {}", deviceProperty);
        selector = DesktopDeviceSelector.forFingerprint(deviceProperty);
      }
      Optional<DesktopDeviceRecord> record = yubikit.getDeviceBySelector(selector);
      if (record.isPresent()) {
        return record.get().getDevice();
      }
      // List connected devices to help diagnose (fingerprints change on reconnect)
      List<DesktopDeviceRecord> connected = yubikit.listDeviceRecords();
      StringBuilder sb = new StringBuilder();
      sb.append("No YubiKey matching '").append(deviceProperty).append("' found. ");
      sb.append("Check -D").append(DEVICE_PROPERTY).append(" value.");
      if (!connected.isEmpty()) {
        sb.append(" Connected devices: ");
        for (DesktopDeviceRecord r : connected) {
          sb.append(r.getSelector()).append(" ");
        }
      }
      throw new IllegalStateException(sb.toString().trim());
    }

    List<DesktopDeviceRecord> records = yubikit.listDeviceRecords();
    if (records.isEmpty()) {
      throw new IllegalStateException("No YubiKey devices connected");
    }
    if (records.size() == 1) {
      return records.get(0).getDevice();
    }

    // Multiple devices connected — require explicit selection
    StringBuilder sb = new StringBuilder();
    sb.append("Multiple YubiKey devices connected (").append(records.size()).append("). ");
    sb.append("Set -D").append(DEVICE_PROPERTY).append("=<SERIAL or FINGERPRINT> to select one. ");
    sb.append("Connected devices: ");
    for (DesktopDeviceRecord r : records) {
      sb.append(r.getSelector()).append(" ");
    }
    throw new IllegalStateException(sb.toString().trim());
  }

  public void returnSession(YubiKeyDevice ignoredDevice) {
    logger.debug("Device returned");
  }
}

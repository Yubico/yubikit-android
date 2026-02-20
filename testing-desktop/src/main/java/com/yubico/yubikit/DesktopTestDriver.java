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
   * System property to specify a YubiKey serial number for device selection. Set {@code
   * -Dyubikit.serial=123456} to target a specific device when multiple YubiKeys are connected.
   */
  public static final String SERIAL_PROPERTY = "yubikit.serial";

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
   *   <li>If the system property {@value #SERIAL_PROPERTY} is set, selects the device with that
   *       serial number.
   *   <li>If exactly one device is connected, uses that device.
   *   <li>If multiple devices are connected and no serial is specified, throws {@link
   *       IllegalStateException} with instructions to set the system property.
   * </ul>
   *
   * @return the selected YubiKey device
   * @throws InterruptedException if interrupted while waiting
   */
  public YubiKeyDevice awaitSession() throws InterruptedException {
    String serialProperty = System.getProperty(SERIAL_PROPERTY);
    if (serialProperty != null) {
      int serial = Integer.parseInt(serialProperty);
      logger.info("Selecting device by serial number: {}", serial);
      DesktopDeviceSelector selector = DesktopDeviceSelector.forSerial(serial);
      Optional<DesktopDeviceRecord> record = yubikit.getDeviceBySelector(selector);
      if (record.isPresent()) {
        return record.get().getDevice();
      }
      throw new IllegalStateException(
          "No YubiKey with serial " + serial + " found. Check -D" + SERIAL_PROPERTY + " value.");
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
    sb.append("Set -D").append(SERIAL_PROPERTY).append("=SERIAL to select one. ");
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

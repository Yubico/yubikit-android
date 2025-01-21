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
package com.yubico.yubikit.testing.desktop;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.desktop.OperatingSystem;
import com.yubico.yubikit.desktop.YubiKitManager;
import org.slf4j.LoggerFactory;

public class DesktopTestDriver {

  private final YubiKitManager yubikit;

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(DesktopTestDriver.class);

  public DesktopTestDriver() {
    if (OperatingSystem.isMac()) {
      System.setProperty(
          "sun.security.smartcardio.library",
          "/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC");
    }
    yubikit = new YubiKitManager();
  }

  public YubiKeyDevice awaitSession() throws InterruptedException {
    return yubikit.listAllDevices().keySet().iterator().next();
  }

  public void returnSession(YubiKeyDevice ignoredDevice) {
    Logger.debug(logger, "Device returned");
  }
}

/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.desktop.app;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.desktop.OperatingSystem;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.management.DeviceInfo;
import java.io.IOException;
import java.util.Map;
import org.slf4j.LoggerFactory;

public class DesktopApp {

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(DesktopApp.class);

  public static void main(String[] argv) {
    if (OperatingSystem.isMac()) {
      System.setProperty(
          "sun.security.smartcardio.library",
          "/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC");
    }

    System.out.println("Insert YubiKey now...");

    YubiKitManager manager = new YubiKitManager();
    Map<YubiKeyDevice, DeviceInfo> devices = manager.listAllDevices();
    logger.debug("Devices: {}", devices);
    for (Map.Entry<YubiKeyDevice, DeviceInfo> entry : devices.entrySet()) {
      YubiKeyDevice device = entry.getKey();
      DeviceInfo info = entry.getValue();
      logger.debug("Found key: {} {}", device, info);
      if (device.supportsConnection(SmartCardConnection.class)) {
        logger.debug("Request CCID connection");
        device.requestConnection(
            SmartCardConnection.class,
            value -> {
              try {
                logger.debug("Got CCID connection {}", value.getValue());
              } catch (IOException e) {
                logger.error("Failed to get CCID: ", e);
              }
            });
      }
      if (device.supportsConnection(OtpConnection.class)) {
        logger.debug("Request OTP connection");
        device.requestConnection(
            OtpConnection.class,
            value -> {
              try {
                logger.debug("Got OTP connection {}", value.getValue());
              } catch (IOException e) {
                logger.error("Failed to get OTP: ", e);
              }
            });
      }
      if (device.supportsConnection(FidoConnection.class)) {
        logger.debug("Request FIDO connection");
        device.requestConnection(
            FidoConnection.class,
            value -> {
              try {
                logger.debug("Got FIDO connection {}", value.getValue());
              } catch (IOException e) {
                logger.error("Failed to get FIDO: ", e);
              }
            });
      }
    }

    logger.debug("Sleeping...");
    try {
      Thread.sleep(5000);
    } catch (InterruptedException e) {
      throw new RuntimeException(e);
    }

    logger.debug("Application exited");
  }
}

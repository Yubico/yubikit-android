/*
 * Copyright (C) 2024-2025 Yubico.
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
import com.yubico.yubikit.desktop.CompositeDevice;
import com.yubico.yubikit.desktop.OperatingSystem;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.oath.OathSession;
import com.yubico.yubikit.yubiotp.ConfigurationState;
import com.yubico.yubikit.yubiotp.Slot;
import com.yubico.yubikit.yubiotp.YubiOtpSession;
import java.util.List;
import java.util.Map;
import org.slf4j.LoggerFactory;

public class DesktopApp {

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(DesktopApp.class);

  public static void main(String[] argv) throws Exception {
    if (OperatingSystem.isMac()) {

      System.setProperty(
          "sun.security.smartcardio.library",
          "/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC");
    }

    YubiKitManager manager = new YubiKitManager();
    Map<YubiKeyDevice, DeviceInfo> devices = manager.listAllDevices();
    if (devices.isEmpty()) {
      logger.info("No devices are connected.");
    } else {
      logger.info("Found {} devices", devices.size());
    }

    for (Map.Entry<YubiKeyDevice, DeviceInfo> entry : devices.entrySet()) {
      YubiKeyDevice device = entry.getKey();
      DeviceInfo info = entry.getValue();

      String deviceType = device.getClass().getSimpleName();

      if (device instanceof CompositeDevice) {
        CompositeDevice compositeDevice = (CompositeDevice) device;
        deviceType += " (" + compositeDevice.getPidGroup().getPid() + ")";
      }

      logger.info(
          "- {}:{}/{}/{}",
          deviceType,
          info.getFormFactor(),
          info.getVersion(),
          info.getSerialNumber());

      if (device.supportsConnection(SmartCardConnection.class)) {
        device.requestConnection(
            SmartCardConnection.class,
            value -> {
              try {
                SmartCardConnection connection = value.getValue();
                OathSession oath = new OathSession(connection);
                logger.info(
                    "    Device supports SmartCardConnection. OATH applet version is: {}",
                    oath.getVersion());
              } catch (Exception e) {
                logger.error("      SmartCard connection failed with error: {}", e.getMessage());
              }
            });

        sleep();
      } else {
        logger.info("    Device does not support SmartCardConnection");
      }

      if (device.supportsConnection(FidoConnection.class)) {
        device.requestConnection(
            FidoConnection.class,
            value -> {
              try {
                FidoConnection fidoConnection = value.getValue();
                Ctap2Session ctap2Session = new Ctap2Session(fidoConnection);
                final List<String> versions = ctap2Session.getCachedInfo().getVersions();
                logger.info(
                    "    Device supports FidoConnection. Supported versions: {}",
                    String.join(", ", versions));
              } catch (Exception e) {
                logger.error("      FIDO connection failed with error: {}", e.getMessage());
              }
            });
        sleep();
      } else {
        logger.info("    Device does not support FidoConnection");
      }

      if (device.supportsConnection(OtpConnection.class)) {
        device.requestConnection(
            OtpConnection.class,
            value -> {
              try {
                OtpConnection otpConnection = value.getValue();
                YubiOtpSession yubiOtpSession = new YubiOtpSession(otpConnection);
                ConfigurationState state = yubiOtpSession.getConfigurationState();
                String configuredSlots = " ";
                if (state.isConfigured(Slot.ONE)) {
                  configuredSlots += "SLOT1 ";
                }
                if (state.isConfigured(Slot.TWO)) {
                  configuredSlots += "SLOT2";
                }
                logger.info(
                    "    Device supports OtpConnection. Configured slots:{}", configuredSlots);
              } catch (Exception e) {
                logger.error("      OTP connection failed with error: {}", e.getMessage());
              }
            });
        sleep();
      } else {
        logger.info("    Device does not support OtpConnection");
      }
    }

    for (YubiKeyDevice yubiKeyDevice : devices.keySet()) {
      if (yubiKeyDevice instanceof CompositeDevice) {
        CompositeDevice usbYubiKeyDevice = (CompositeDevice) yubiKeyDevice;
        usbYubiKeyDevice.close();
      }
    }
    logger.info("Application exited");
  }

  private static void sleep() {
    try {
      Thread.sleep(200);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    }
  }
}

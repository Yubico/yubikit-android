/*
 * Copyright (C) 2024-2026 Yubico.
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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.desktop.DesktopDeviceRecord;
import com.yubico.yubikit.desktop.DesktopDeviceSelector;
import com.yubico.yubikit.desktop.OperatingSystem;
import com.yubico.yubikit.desktop.YubiKitManager;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.Nullable;

public class DesktopApp {

  private static final String APP_NAME = "DesktopApp";

  public static void main(String[] argv) {
    if (OperatingSystem.isMac()) {
      System.setProperty(
          "sun.security.smartcardio.library",
          "/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC");
    }

    // Parse arguments
    String serialArg = null;
    String fingerprintArg = null;
    String command = null;

    int i = 0;
    while (i < argv.length) {
      String arg = argv[i];
      if ("--serial".equals(arg)) {
        if (i + 1 >= argv.length) {
          System.err.println("Error: --serial requires a value.");
          System.exit(1);
        }
        serialArg = argv[++i];
      } else if ("--fingerprint".equals(arg)) {
        if (i + 1 >= argv.length) {
          System.err.println("Error: --fingerprint requires a value.");
          System.exit(1);
        }
        fingerprintArg = argv[++i];
      } else if ("--help".equals(arg) || "-h".equals(arg)) {
        printHelp();
        return;
      } else if (arg.startsWith("-")) {
        System.err.println("Error: Unknown option: " + arg);
        printHelp();
        System.exit(1);
      } else {
        if (command != null) {
          System.err.println("Error: Unexpected argument: " + arg);
          printHelp();
          System.exit(1);
        }
        command = arg;
      }
      i++;
    }

    if (command == null) {
      printHelp();
      return;
    }

    if (serialArg != null && fingerprintArg != null) {
      System.err.println("Error: --serial and --fingerprint are mutually exclusive.");
      System.exit(1);
    }

    YubiKitManager manager = new YubiKitManager();

    switch (command) {
      case "list":
        commandList(manager);
        break;
      case "info":
        commandInfo(manager, serialArg, fingerprintArg);
        break;
      default:
        System.err.println("Error: Unknown command: " + command);
        printHelp();
        System.exit(1);
    }
  }

  private static void printHelp() {
    System.out.println("Usage: " + APP_NAME + " [options] <command>");
    System.out.println();
    System.out.println("Commands:");
    System.out.println("  list    List all connected YubiKeys");
    System.out.println("  info    Show device info for a YubiKey");
    System.out.println();
    System.out.println("Options:");
    System.out.println("  --serial <serial>          Select device by serial number");
    System.out.println("  --fingerprint <fingerprint> Select device by fingerprint");
    System.out.println("  -h, --help                 Show this help message");
    System.out.println();
    System.out.println("Examples:");
    System.out.println("  " + APP_NAME + " list");
    System.out.println("  " + APP_NAME + " info");
    System.out.println("  " + APP_NAME + " --serial 12345678 info");
    System.out.println("  " + APP_NAME + " --fingerprint \"USB_0001\" info");
  }

  private static void commandList(YubiKitManager manager) {
    List<DesktopDeviceRecord> records = manager.listDeviceRecords();
    if (records.isEmpty()) {
      System.out.println("No YubiKey devices connected.");
      return;
    }

    System.out.println("Connected YubiKeys (" + records.size() + "):");
    System.out.println();
    for (int idx = 0; idx < records.size(); idx++) {
      DesktopDeviceRecord record = records.get(idx);
      DeviceInfo info = record.getInfo();
      DesktopDeviceSelector selector = record.getSelector();

      System.out.println("Device #" + (idx + 1) + ":");
      System.out.println(
          "  Serial:      "
              + (info.getSerialNumber() != null ? info.getSerialNumber() : "(not available)"));
      System.out.println(
          "  Fingerprint: "
              + (selector.getFingerprint() != null
                  ? selector.getFingerprint()
                  : "(serial-based selector)"));
      System.out.println("  Version:     " + info.getVersion());
      System.out.println("  Form factor: " + info.getFormFactor());
      System.out.println();
    }
  }

  private static void commandInfo(
      YubiKitManager manager, @Nullable String serialArg, @Nullable String fingerprintArg) {

    DesktopDeviceRecord record;

    if (serialArg != null) {
      int serial;
      try {
        serial = Integer.parseInt(serialArg);
      } catch (NumberFormatException e) {
        System.err.println("Error: Invalid serial number: " + serialArg);
        System.exit(1);
        return;
      }
      Optional<DesktopDeviceRecord> found = manager.getDeviceBySerial(serial);
      if (!found.isPresent()) {
        System.err.println("Error: No YubiKey with serial " + serial + " found.");
        System.exit(1);
        return;
      }
      record = found.get();
    } else if (fingerprintArg != null) {
      DesktopDeviceSelector selector = DesktopDeviceSelector.forFingerprint(fingerprintArg);
      Optional<DesktopDeviceRecord> found = manager.getDeviceBySelector(selector);
      if (!found.isPresent()) {
        System.err.println("Error: No YubiKey with fingerprint \"" + fingerprintArg + "\" found.");
        System.exit(1);
        return;
      }
      record = found.get();
    } else {
      // No selector: require exactly one device
      List<DesktopDeviceRecord> records = manager.listDeviceRecords();
      if (records.isEmpty()) {
        System.err.println("Error: No YubiKey devices connected.");
        System.exit(1);
        return;
      }
      if (records.size() > 1) {
        System.err.println(
            "Error: Multiple YubiKeys connected ("
                + records.size()
                + "). Use --serial or --fingerprint to select a device.");
        System.err.println();
        System.err.println("Connected devices:");
        for (DesktopDeviceRecord r : records) {
          DeviceInfo rInfo = r.getInfo();
          System.err.println(
              "  Serial: "
                  + (rInfo.getSerialNumber() != null ? rInfo.getSerialNumber() : "(n/a)")
                  + "  Fingerprint: "
                  + (r.getSelector().getFingerprint() != null
                      ? r.getSelector().getFingerprint()
                      : "(serial-based)"));
        }
        System.exit(1);
        return;
      }
      record = records.get(0);
    }

    printDeviceInfo(record);
  }

  private static void printDeviceInfo(DesktopDeviceRecord record) {
    DeviceInfo info = record.getInfo();
    DesktopDeviceSelector selector = record.getSelector();

    System.out.println("YubiKey Device Info");
    System.out.println("===================");
    System.out.println(
        "Serial number:  "
            + (info.getSerialNumber() != null ? info.getSerialNumber() : "(not available)"));
    System.out.println("Firmware:       " + info.getVersion());
    System.out.println("Form factor:    " + info.getFormFactor());
    System.out.println("FIPS:           " + (info.isFips() ? "Yes" : "No"));
    System.out.println("SKY:            " + (info.isSky() ? "Yes" : "No"));
    System.out.println("Locked:         " + (info.isLocked() ? "Yes" : "No"));
    if (info.getPartNumber() != null && !info.getPartNumber().isEmpty()) {
      System.out.println("Part number:    " + info.getPartNumber());
    }
    System.out.println("PIN complexity: " + (info.getPinComplexity() ? "Yes" : "No"));

    if (info.hasTransport(Transport.USB)) {
      int supported = info.getSupportedCapabilities(Transport.USB);
      System.out.println();
      System.out.println("USB capabilities: " + formatCapabilities(supported));
    }

    if (info.hasTransport(Transport.NFC)) {
      int supported = info.getSupportedCapabilities(Transport.NFC);
      System.out.println();
      System.out.println("NFC capabilities: " + formatCapabilities(supported));
    }

    System.out.println();
    System.out.println("Selector:       " + selector);
  }

  private static String formatCapabilities(int capabilityFlags) {
    List<String> names = new ArrayList<>();
    for (Capability cap : Capability.values()) {
      if ((capabilityFlags & cap.bit) != 0) {
        names.add(cap.name());
      }
    }
    return names.isEmpty() ? "(none)" : String.join(", ", names);
  }
}

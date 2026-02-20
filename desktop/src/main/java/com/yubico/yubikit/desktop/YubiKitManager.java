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
package com.yubico.yubikit.desktop;

import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.desktop.hid.HidManager;
import com.yubico.yubikit.desktop.pcsc.PcscManager;
import com.yubico.yubikit.management.DeviceInfo;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class YubiKitManager {
  private final PcscManager pcscManager;
  private final HidManager hidManager;

  private final Logger logger = LoggerFactory.getLogger(YubiKitManager.class);

  public YubiKitManager(PcscManager pcscManager, HidManager hidManager) {
    this.pcscManager = pcscManager;
    this.hidManager = hidManager;
  }

  public YubiKitManager() {
    this(new PcscManager(), new HidManager());
  }

  List<? extends UsbYubiKeyDevice> listDevices(Class<? extends YubiKeyConnection> connectionType) {
    if (SmartCardConnection.class.isAssignableFrom(connectionType)) {
      return pcscManager.getDevices();
    } else if (OtpConnection.class.isAssignableFrom(connectionType)) {
      return hidManager.getOtpDevices();
    } else if (FidoConnection.class.isAssignableFrom(connectionType)) {
      return hidManager.getFidoDevices();
    }
    throw new IllegalStateException("Unsupported connection type");
  }

  public Map<YubiKeyDevice, DeviceInfo> listAllDevices(
      Set<Class<? extends YubiKeyConnection>> connectionTypes) {
    Map<UsbPid, UsbPidGroup> groups = buildGroups(connectionTypes);

    Map<YubiKeyDevice, DeviceInfo> devices = new LinkedHashMap<>();
    for (UsbPidGroup group : groups.values()) {
      devices.putAll(group.getDevices());
    }
    return devices;
  }

  public Map<YubiKeyDevice, DeviceInfo> listAllDevices() {
    return listAllDevices(
        new HashSet<>(
            Arrays.asList(SmartCardConnection.class, FidoConnection.class, OtpConnection.class)));
  }

  /**
   * Lists all connected YubiKey devices as {@link DesktopDeviceRecord} instances.
   *
   * <p>Each record contains the device, its info, and a {@link DesktopDeviceSelector} that can be
   * used to target the device for connection operations. The selector is serial-based when the
   * device serial number is available, and fingerprint-based otherwise.
   *
   * <p>The returned list is ordered by serial number (nulls last), then by fingerprint.
   *
   * <p><b>Usage example:</b>
   *
   * <pre>{@code
   * YubiKitManager mgr = new YubiKitManager();
   * List<DesktopDeviceRecord> devices = mgr.listDeviceRecords();
   *
   * DesktopDeviceSelector sel = devices.get(0).getSelector(); // or forSerial(123456)
   * try (FidoConnection c = mgr.openConnection(sel, FidoConnection.class)) {
   *     // run operation on the selected device
   * }
   * }</pre>
   *
   * @return a list of device records, sorted deterministically
   * @see #getDeviceBySerial(int)
   * @see #getDeviceBySelector(DesktopDeviceSelector)
   */
  public List<DesktopDeviceRecord> listDeviceRecords() {
    return listDeviceRecords(
        new HashSet<>(
            Arrays.asList(SmartCardConnection.class, FidoConnection.class, OtpConnection.class)));
  }

  /**
   * Lists all connected YubiKey devices matching the given connection types as {@link
   * DesktopDeviceRecord} instances.
   *
   * @param connectionTypes the connection types to enumerate
   * @return a list of device records, sorted deterministically
   */
  public List<DesktopDeviceRecord> listDeviceRecords(
      Set<Class<? extends YubiKeyConnection>> connectionTypes) {
    Map<UsbPid, UsbPidGroup> groups = buildGroups(connectionTypes);

    List<DesktopDeviceRecord> records = new ArrayList<>();
    for (UsbPidGroup group : groups.values()) {
      Map<YubiKeyDevice, DeviceInfo> devices = group.getDevices();
      for (Map.Entry<YubiKeyDevice, DeviceInfo> entry : devices.entrySet()) {
        YubiKeyDevice device = entry.getKey();
        DeviceInfo info = entry.getValue();
        DesktopDeviceSelector selector = buildSelector(device, info);
        records.add(new DesktopDeviceRecord(device, info, selector));
      }
    }

    // Sort deterministically: serial (nulls last), then fingerprint
    records.sort(
        Comparator.<DesktopDeviceRecord, Integer>comparing(
                r ->
                    r.getInfo().getSerialNumber() != null
                        ? r.getInfo().getSerialNumber()
                        : Integer.MAX_VALUE)
            .thenComparing(r -> r.getSelector().toString()));

    return records;
  }

  /**
   * Returns the device record matching the given serial number, if present.
   *
   * @param serial the serial number to search for
   * @return an {@link Optional} containing the matching record, or empty if not found
   */
  public Optional<DesktopDeviceRecord> getDeviceBySerial(int serial) {
    return listDeviceRecords().stream()
        .filter(r -> Integer.valueOf(serial).equals(r.getInfo().getSerialNumber()))
        .findFirst();
  }

  /**
   * Returns the device record matching the given selector, if present.
   *
   * <p>For serial-based selectors, matches by serial number. For fingerprint-based selectors,
   * matches by fingerprint.
   *
   * @param selector the selector to match
   * @return an {@link Optional} containing the matching record, or empty if not found
   */
  public Optional<DesktopDeviceRecord> getDeviceBySelector(DesktopDeviceSelector selector) {
    return listDeviceRecords().stream().filter(r -> matchesSelector(r, selector)).findFirst();
  }

  /**
   * Returns the single connected device, or throws if zero or more than one device is connected.
   *
   * <p>This mirrors the yubikey-manager behavior of requiring explicit device selection when
   * multiple devices are present.
   *
   * @return the single device record
   * @throws IllegalStateException if zero or more than one device is connected
   */
  public DesktopDeviceRecord requireSingleDevice() {
    List<DesktopDeviceRecord> records = listDeviceRecords();
    if (records.isEmpty()) {
      throw new IllegalStateException("No YubiKey devices connected");
    }
    if (records.size() > 1) {
      String deviceList =
          records.stream().map(r -> r.getSelector().toString()).collect(Collectors.joining(", "));
      throw new IllegalStateException(
          "Multiple YubiKey devices connected ("
              + records.size()
              + "): "
              + deviceList
              + ". Use a DesktopDeviceSelector to specify which device to use.");
    }
    return records.get(0);
  }

  /**
   * Opens a connection of the given type to the device identified by the selector.
   *
   * <p>This method enumerates all connected devices, resolves the target device matching the
   * selector, and opens a connection of the requested type on it.
   *
   * @param selector the selector identifying the target device
   * @param connectionType the type of connection to open
   * @return an open connection to the selected device
   * @throws IOException if the device is not found or the connection cannot be opened
   */
  public <T extends YubiKeyConnection> T openConnection(
      DesktopDeviceSelector selector, Class<T> connectionType) throws IOException {
    Set<Class<? extends YubiKeyConnection>> connectionTypes =
        new HashSet<>(
            Arrays.asList(SmartCardConnection.class, FidoConnection.class, OtpConnection.class));
    Map<UsbPid, UsbPidGroup> groups = buildGroups(connectionTypes);

    for (UsbPidGroup group : groups.values()) {
      if (!group.supportsConnection(connectionType)) {
        continue;
      }
      String key = group.resolveKey(selector);
      if (key != null) {
        return group.openConnection(key, connectionType);
      }
      // Try unresolved devices within this group
      try {
        return group.openConnection(selector, connectionType);
      } catch (IOException e) {
        logger.debug(
            "Selector {} not found in PID group {}: {}", selector, group.getPid(), e.getMessage());
      }
    }
    throw new IOException(
        "No device matching selector " + selector + " supports " + connectionType.getSimpleName());
  }

  private Map<UsbPid, UsbPidGroup> buildGroups(
      Set<Class<? extends YubiKeyConnection>> connectionTypes) {
    Map<UsbPid, UsbPidGroup> groups = new HashMap<>();
    for (Class<? extends YubiKeyConnection> connectionType : connectionTypes) {
      logger.debug("Enumerate devices for {}", connectionType);
      for (UsbYubiKeyDevice device : listDevices(connectionType)) {
        UsbPid pid = device.getPid();
        logger.debug("Found device with PID {}", pid);
        if (!groups.containsKey(pid)) {
          groups.put(pid, new UsbPidGroup(pid));
        }
        groups.get(pid).add(connectionType, device, false);
      }
    }
    return groups;
  }

  private static DesktopDeviceSelector buildSelector(YubiKeyDevice device, DeviceInfo info) {
    Integer serial = info.getSerialNumber();
    if (serial != null) {
      return DesktopDeviceSelector.forSerial(serial);
    }
    // Fallback to fingerprint
    if (device instanceof CompositeDevice) {
      return DesktopDeviceSelector.forFingerprint(((CompositeDevice) device).getFingerprint());
    }
    if (device instanceof UsbYubiKeyDevice) {
      return DesktopDeviceSelector.forFingerprint(((UsbYubiKeyDevice) device).getFingerprint());
    }
    // Last resort: use device class + hashCode as a pseudo-fingerprint
    return DesktopDeviceSelector.forFingerprint(
        device.getClass().getSimpleName() + "@" + Integer.toHexString(device.hashCode()));
  }

  private static boolean matchesSelector(
      DesktopDeviceRecord record, DesktopDeviceSelector selector) {
    if (selector.getSerial() != null) {
      return selector.getSerial().equals(record.getInfo().getSerialNumber());
    }
    if (selector.getFingerprint() != null) {
      return selector.getFingerprint().equals(record.getSelector().getFingerprint());
    }
    return false;
  }
}

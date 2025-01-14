/*
 * Copyright (C) 2022,2024 Yubico.
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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbInterface;
import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.YubiKeyType;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.support.DeviceUtil;
import java.io.IOException;
import java.util.*;
import org.slf4j.LoggerFactory;

public class UsbPidGroup {
  final UsbPid pid;

  private final Map<String, DeviceInfo> infos = new HashMap<>();
  private final Map<String, Map<Integer, UsbYubiKeyDevice>> resolved = new HashMap<>();
  private final Map<Integer, List<UsbYubiKeyDevice>> unresolved = new HashMap<>();
  private final Map<Integer, Integer> devCount = new HashMap<>();
  private final Set<String> fingerprints = new HashSet<>();
  private final long ctime = System.currentTimeMillis();

  private final org.slf4j.Logger logger = LoggerFactory.getLogger(UsbPidGroup.class);

  UsbPidGroup(UsbPid pid) {
    this.pid = pid;
  }

  private String buildKey(DeviceInfo info) {
    return ""
        + info.getSerialNumber()
        + info.getVersion()
        + info.getFormFactor()
        + info.getSupportedCapabilities(Transport.USB)
        + info.getConfig()
        + info.isLocked()
        + info.isFips()
        + info.isSky();
  }

  int getUsbInterface(Class<? extends YubiKeyConnection> connectionType) {
    if (SmartCardConnection.class.isAssignableFrom(connectionType)) {
      return UsbInterface.CCID;
    }
    if (OtpConnection.class.isAssignableFrom(connectionType)) {
      return UsbInterface.OTP;
    }
    if (FidoConnection.class.isAssignableFrom(connectionType)) {
      return UsbInterface.FIDO;
    }
    throw new IllegalArgumentException();
  }

  void add(
      Class<? extends YubiKeyConnection> connectionType,
      UsbYubiKeyDevice device,
      boolean forceResolve) {
    Logger.trace(logger, "Add device node {}{}", device, connectionType);
    int usbInterface = getUsbInterface(connectionType);
    fingerprints.add(device.getFingerprint());
    devCount.put(usbInterface, devCount.getOrDefault(usbInterface, 0) + 1);
    if (forceResolve || resolved.size() < devCount.values().stream().reduce(0, Math::max)) {
      try (YubiKeyConnection connection = device.openConnection(connectionType)) {
        DeviceInfo info = DeviceUtil.readInfo(connection, pid);
        String key = buildKey(info);
        infos.put(key, info);
        if (!resolved.containsKey(key)) {
          resolved.put(key, new HashMap<>());
        }
        resolved.get(key).put(usbInterface, device);
        Integer serialNumber = info.getSerialNumber();
        Logger.trace(
            logger,
            "Resolved device {}",
            serialNumber != null ? serialNumber : "without serial number");
        return;
      } catch (IOException e) {
        Logger.error(logger, "Failed opening device. ", e);
      }
    }
    if (!unresolved.containsKey(usbInterface)) {
      unresolved.put(usbInterface, new ArrayList<>());
    }
    unresolved.get(usbInterface).add(device);
  }

  boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType) {
    return (getUsbInterface(connectionType) & pid.usbInterfaces) != 0;
  }

  <T extends YubiKeyConnection> T openConnection(String key, Class<T> connectionType)
      throws IOException {
    int usbInterface = getUsbInterface(connectionType);
    UsbYubiKeyDevice device = resolved.get(key).get(usbInterface);
    if (device != null) {
      return device.openConnection(connectionType);
    }

    Logger.debug(logger, "Resolve device for {}, {}", connectionType, key);
    List<UsbYubiKeyDevice> devices = unresolved.getOrDefault(usbInterface, new ArrayList<>());
    Logger.debug(logger, "Unresolved: {}", devices);
    List<UsbYubiKeyDevice> failed = new ArrayList<>();
    try {
      while (!devices.isEmpty()) {
        device = devices.remove(0);
        Logger.debug(logger, "Candidate: {}", device);
        try {
          T connection = device.openConnection(connectionType);
          DeviceInfo info = DeviceUtil.readInfo(connection, pid);
          String deviceKey = buildKey(info);
          if (infos.containsKey(deviceKey)) {
            if (!resolved.containsKey(deviceKey)) {
              resolved.put(deviceKey, new HashMap<>());
            }
            resolved.get(deviceKey).put(usbInterface, device);
            if (deviceKey.equals(key)) {
              return connection;
            } else if (pid.type == YubiKeyType.NEO && devices.isEmpty()) {
              Logger.debug(logger, "Resolved last NEO device without serial");
              return connection;
            }
          }
        } catch (IOException e) {
          Logger.error(logger, "Failed opening candidate device: ", e);
          failed.add(device);
        }
      }
    } finally {
      devices.addAll(failed);
    }

    throw new IOException("Failed to open connection");
  }

  <T extends YubiKeyConnection> void requestConnection(
      String key, Class<T> connectionType, Callback<Result<T, IOException>> callback) {
    int usbInterface = getUsbInterface(connectionType);
    UsbYubiKeyDevice device = resolved.get(key).get(usbInterface);
    if (device != null) {
      device.requestConnection(connectionType, callback);
    } else {
      Logger.debug(logger, "Resolve device for {}, {}", connectionType, key);
      List<UsbYubiKeyDevice> devices = unresolved.getOrDefault(usbInterface, new ArrayList<>());
      Logger.debug(logger, "Unresolved: {}", devices);
      List<UsbYubiKeyDevice> failed = new ArrayList<>();
      try {
        while (!devices.isEmpty()) {
          device = devices.remove(0);
          Logger.debug(logger, "Candidate: {}", device);
          try (T connection = device.openConnection(connectionType)) {
            DeviceInfo info = DeviceUtil.readInfo(connection, pid);
            String deviceKey = buildKey(info);
            if (infos.containsKey(deviceKey)) {
              if (!resolved.containsKey(deviceKey)) {
                resolved.put(deviceKey, new HashMap<>());
              }
              resolved.get(deviceKey).put(usbInterface, device);
              if (deviceKey.equals(key)) {
                device.requestConnection(connectionType, callback);
                return;
              } else if (pid.type == YubiKeyType.NEO && devices.isEmpty()) {
                Logger.debug(logger, "Resolved last NEO device without serial");
                device.requestConnection(connectionType, callback);
                return;
              }
            }
          } catch (IOException e) {
            Logger.error(logger, "Failed opening candidate device: ", e);
            failed.add(device);
          }
        }
      } finally {
        devices.addAll(failed);
      }

      // TODO
      /*
          if self._devcount[iface] < len(self._infos):
          logger.debug(f"Checking for more devices over {iface!s}")
          for dev in _CONNECTION_LIST_MAPPING[conn_type]():
              if self._pid == dev.pid and dev.fingerprint not in self._fingerprints:
                  self.add(conn_type, dev, True)

          resolved = self._resolved[key].get(iface)
          if resolved:
              return resolved.open_connection(conn_type)

      # Retry if we are within a 5 second period after creation,
      # as not all USB interface become usable at the exact same time.
      if time() < self._ctime + 5:
          logger.debug("Device not found, retry in 1s")
          sleep(1.0)
          return self.connect(key, conn_type)

      raise ValueError("Failed to connect to the device")
           */
    }
  }

  Map<YubiKeyDevice, DeviceInfo> getDevices() {
    Map<YubiKeyDevice, DeviceInfo> devices = new LinkedHashMap<>();
    for (Map.Entry<String, DeviceInfo> entry : infos.entrySet()) {
      devices.put(new CompositeDevice(this, entry.getKey()), entry.getValue());
    }
    return devices;
  }

  public UsbPid getPid() {
    return pid;
  }
}

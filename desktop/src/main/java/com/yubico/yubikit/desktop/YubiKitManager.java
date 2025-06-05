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
package com.yubico.yubikit.desktop;

import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.desktop.hid.HidManager;
import com.yubico.yubikit.desktop.pcsc.PcscManager;
import com.yubico.yubikit.management.DeviceInfo;
import java.util.*;
import org.slf4j.LoggerFactory;

public class YubiKitManager {
  private final PcscManager pcscManager;
  private final HidManager hidManager;

  private final org.slf4j.Logger logger = LoggerFactory.getLogger(YubiKitManager.class);

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
    Map<UsbPid, UsbPidGroup> groups = new HashMap<>();
    for (Class<? extends YubiKeyConnection> connectionType : connectionTypes) {
      Logger.debug(logger, "Enumerate devices for {}", connectionType);
      for (UsbYubiKeyDevice device : listDevices(connectionType)) {
        UsbPid pid = device.getPid();
        Logger.debug(logger, "Found device with PID {}", pid);
        if (!groups.containsKey(pid)) {
          groups.put(pid, new UsbPidGroup(pid));
        }
        groups.get(pid).add(connectionType, device, false);
      }
    }

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
}

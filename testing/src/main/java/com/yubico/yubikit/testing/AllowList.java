/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.testing;

import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.support.DeviceUtil;
import java.io.IOException;
import java.util.List;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AllowList {

  private static final Logger logger = LoggerFactory.getLogger(AllowList.class);
  private final AllowListProvider allowListProvider;
  private final List<Integer> allowedSerials;

  public interface AllowListProvider {
    /**
     * Retrieves a list of allowed serial numbers.
     *
     * @return a list of allowed serial numbers as integers.
     */
    List<Integer> getList();

    String onInvalidInputErrorMessage();

    String onNotAllowedErrorMessage(Integer serialNumber);
  }

  public AllowList(AllowListProvider allowListProvider) {
    this.allowListProvider = allowListProvider;
    this.allowedSerials = allowListProvider.getList();
    if (allowedSerials.isEmpty()) {
      logger.error("{}", allowListProvider.onInvalidInputErrorMessage());
      System.exit(-1);
    }
  }

  // verify that the device is in the allow-list
  public void verify(YubiKeyDevice connectedDevice, @Nullable UsbPid pid) {
    Integer serialNumber = getDeviceSerialNumber(connectedDevice, pid);
    if (!isDeviceAllowed(serialNumber)) {
      logger.error("{}", allowListProvider.onNotAllowedErrorMessage(serialNumber));
      System.exit(-1);
    }
  }

  private boolean isDeviceAllowed(@Nullable Integer serialNumber) {
    if (serialNumber == null) {
      logger.error("Device serial number is null, not allowed");
      return false;
    }

    return allowedSerials.contains(serialNumber);
  }

  @Nullable
  private Integer getDeviceSerialNumber(YubiKeyDevice device, @Nullable UsbPid pid) {

    if (device.supportsConnection(SmartCardConnection.class)) {
      try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
        return getDeviceSerialNumber(connection, pid);
      } catch (Exception e) {
        logger.error("Error opening SmartCard connection", e);
      }
    }

    if (device.supportsConnection(FidoConnection.class)) {
      try (FidoConnection connection = device.openConnection(FidoConnection.class)) {
        return getDeviceSerialNumber(connection, pid);
      } catch (Exception e) {
        logger.error("Error opening FIDO connection", e);
      }
    }

    return null;
  }

  @Nullable
  private Integer getDeviceSerialNumber(YubiKeyConnection connection, @Nullable UsbPid pid) {
    try {
      DeviceInfo deviceInfo = DeviceUtil.readInfo(connection, pid);
      Integer serial = deviceInfo.getSerialNumber();
      return serial != null ? serial : 0; // Return 0 if serial number is not available
    } catch (IOException e) {
      logger.error("Error reading device info", e);
      return null;
    }
  }
}

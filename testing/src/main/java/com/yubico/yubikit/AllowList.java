/*
 * Copyright (C) 2025-2026 Yubico.
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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.support.DeviceUtil;
import java.io.IOException;
import java.util.List;
import org.jspecify.annotations.Nullable;
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

    /**
     * Whether a card behind an external reader may be used when it is positively identified as not
     * being a YubiKey. Off by default, and only ever opted into for a single run by the person
     * running the tests: a YubiKey is never admitted this way and still needs its serial number in
     * the list.
     *
     * @return true to admit cards that are not YubiKeys
     */
    default boolean allowExternalCards() {
      return false;
    }

    String onInvalidInputErrorMessage();

    String onNotAllowedErrorMessage(Integer serialNumber);
  }

  // An empty list is not fatal here; only verify() needs the serials.
  public AllowList(AllowListProvider allowListProvider) {
    this.allowListProvider = allowListProvider;
    this.allowedSerials = allowListProvider.getList();
  }

  // verify that the device is in the allow-list
  public void verify(YubiKeyDevice connectedDevice, @Nullable UsbPid pid) {
    // Throw, never System.exit: an exit kills the process and the run emits no report.
    if (allowedSerials.isEmpty()) {
      String message = allowListProvider.onInvalidInputErrorMessage();
      logger.error("{}", message);
      throw new AssertionError(message);
    }

    Integer serialNumber = getDeviceSerialNumber(connectedDevice, pid);
    if (serialNumber == null
        && pid == UsbPid.OTHER
        && allowListProvider.allowExternalCards()
        && isNotYubiKey(connectedDevice)) {
      logger.warn("Using a card that is not a YubiKey behind an external reader");
      return;
    }
    if (!isDeviceAllowed(serialNumber)) {
      String message = allowListProvider.onNotAllowedErrorMessage(serialNumber);
      logger.error("{}", message);
      throw new AssertionError(message);
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

    if (device.supportsConnection(OtpConnection.class)) {
      try (OtpConnection connection = device.openConnection(OtpConnection.class)) {
        return getDeviceSerialNumber(connection, pid);
      } catch (Exception e) {
        logger.error("Error opening OTP connection", e);
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
    if (pid == UsbPid.OTHER) {
      // The PID is the reader's, not the card's, and says nothing about what is inserted. Ask the
      // card itself; anything that is not a YubiKey with a serial number stays unidentified.
      return connection instanceof SmartCardConnection
          ? getSerialNumberFromManagement((SmartCardConnection) connection)
          : null;
    }
    try {
      DeviceInfo deviceInfo = DeviceUtil.readInfo(connection, pid);
      Integer serial = deviceInfo.getSerialNumber();
      return serial != null ? serial : 0; // Return 0 if serial number is not available
    } catch (IllegalArgumentException e) {
      if (connection instanceof SmartCardConnection
          && ((SmartCardConnection) connection).getTransport() == Transport.NFC) {
        // This exception is thrown when readInfo fails to open Management Session
        logger.warn("Using a security Key without serial number", e);
        return 0;
      }
      logger.error("Error reading device info", e);
      return null;
    } catch (IOException e) {
      logger.error("Error reading device info", e);
      return null;
    }
  }

  @Nullable
  private Integer getSerialNumberFromManagement(SmartCardConnection connection) {
    try {
      return new ManagementSession(connection).getDeviceInfo().getSerialNumber();
    } catch (Exception e) {
      logger.error("Error reading device info through the Management application", e);
      return null;
    }
  }

  /**
   * Positively identify a card as not being a YubiKey: it has to answer neither the Management nor
   * the OTP application SELECT, which every YubiKey does. Anything that cannot be established, such
   * as a connection that cannot be opened, counts as "might be a YubiKey".
   */
  private boolean isNotYubiKey(YubiKeyDevice device) {
    if (!device.supportsConnection(SmartCardConnection.class)) {
      return false;
    }
    try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
      return !answersSelect(connection, AppId.MANAGEMENT) && !answersSelect(connection, AppId.OTP);
    } catch (Exception e) {
      logger.error("Could not establish that the card is not a YubiKey", e);
      return false;
    }
  }

  private static boolean answersSelect(SmartCardConnection connection, byte[] aid)
      throws IOException {
    byte[] apdu = new byte[5 + aid.length];
    apdu[1] = (byte) 0xa4; // INS SELECT
    apdu[2] = 0x04; // P1: by name
    apdu[4] = (byte) aid.length;
    System.arraycopy(aid, 0, apdu, 5, aid.length);
    byte[] response = connection.sendAndReceive(apdu);
    if (response.length < 2) {
      throw new IOException("Response too short");
    }
    int sw1 = response[response.length - 2] & 0xff;
    return sw1 == 0x90 || sw1 == 0x61;
  }
}

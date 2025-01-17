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
package com.yubico.yubikit.desktop.pcsc;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbInterface;
import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyType;
import com.yubico.yubikit.desktop.UsbYubiKeyDevice;
import javax.smartcardio.CardTerminal;

public class UsbPcscDevice extends PcscDevice implements UsbYubiKeyDevice {
  private final UsbPid pid;

  public UsbPcscDevice(CardTerminal terminal) {
    super(terminal);
    this.pid = getPidFromName(terminal.getName());
  }

  private static UsbPid getPidFromName(String name) {
    if (!name.toLowerCase().contains("yubikey")) {
      throw new IllegalArgumentException("Given argument is not a USB YubiKey");
    }

    int usbInterfaces = 0;
    if (name.contains("CCID")) {
      usbInterfaces |= UsbInterface.CCID;
    }
    if (name.contains("OTP")) {
      usbInterfaces |= UsbInterface.OTP;
    }
    if (name.contains("FIDO") || name.contains("U2F")) {
      usbInterfaces |= UsbInterface.FIDO;
    }
    YubiKeyType keyType = name.contains("NEO") ? YubiKeyType.NEO : YubiKeyType.YK4;

    for (UsbPid pid : UsbPid.values()) {
      if (pid.type == keyType && pid.usbInterfaces == usbInterfaces) {
        return pid;
      }
    }

    throw new IllegalArgumentException("No known PID for device name");
  }

  @Override
  public Transport getTransport() {
    return Transport.USB;
  }

  @Override
  public String getFingerprint() {
    return getName();
  }

  @Override
  public UsbPid getPid() {
    return pid;
  }
}

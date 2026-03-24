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
package com.yubico.yubikit.desktop.pcsc;

import com.yubico.yubikit.desktop.NfcYubiKeyDevice;
import java.util.*;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

public class PcscManager {
  private static final String YK_READER_NAME = "yubikey";
  private final TerminalFactory terminalFactory;

  public PcscManager(TerminalFactory terminalFactory) {
    this.terminalFactory = terminalFactory;
  }

  public PcscManager() {
    this(TerminalFactory.getDefault());
  }

  /** Result of scanning PC/SC terminals, partitioned into USB YubiKey and NFC readers. */
  public static class PcscDevices {
    private final List<UsbPcscDevice> usbDevices;
    private final List<NfcYubiKeyDevice> nfcDevices;

    PcscDevices(List<UsbPcscDevice> usbDevices, List<NfcYubiKeyDevice> nfcDevices) {
      this.usbDevices = usbDevices;
      this.nfcDevices = nfcDevices;
    }

    public List<UsbPcscDevice> getUsbDevices() {
      return usbDevices;
    }

    public List<NfcYubiKeyDevice> getNfcDevices() {
      return nfcDevices;
    }
  }

  /**
   * Scans all PC/SC terminals with a card present, partitioning them into USB YubiKey readers and
   * NFC readers in a single enumeration pass.
   */
  public PcscDevices scanDevices() {
    List<UsbPcscDevice> usbDevices = new ArrayList<>();
    List<NfcYubiKeyDevice> nfcDevices = new ArrayList<>();
    try {
      for (CardTerminal terminal :
          terminalFactory.terminals().list(CardTerminals.State.CARD_PRESENT)) {
        if (isYubiKeyReader(terminal.getName())) {
          usbDevices.add(new UsbPcscDevice(terminal));
        } else {
          nfcDevices.add(new NfcPcscDevice(terminal));
        }
      }
    } catch (CardException e) {
      throw new RuntimeException(e);
    }
    return new PcscDevices(usbDevices, nfcDevices);
  }

  /** Returns USB YubiKey PC/SC terminals that have a card present. */
  public List<UsbPcscDevice> getDevices() {
    return scanDevices().getUsbDevices();
  }

  /** Returns NFC reader terminals that have a card present (YubiKey tapped). */
  public List<NfcYubiKeyDevice> getNfcDevices() {
    return scanDevices().getNfcDevices();
  }

  private static boolean isYubiKeyReader(String name) {
    return name.toLowerCase().contains(YK_READER_NAME);
  }
}

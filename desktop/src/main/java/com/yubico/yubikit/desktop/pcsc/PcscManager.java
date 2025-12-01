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

import java.util.*;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

public class PcscManager {
  private final TerminalFactory terminalFactory;

  public PcscManager(TerminalFactory terminalFactory) {
    this.terminalFactory = terminalFactory;
  }

  public PcscManager() {
    this(TerminalFactory.getDefault());
  }

  public List<UsbPcscDevice> getDevices() {
    List<UsbPcscDevice> yubikeys = new ArrayList<>();
    try {
      for (CardTerminal device :
          terminalFactory.terminals().list(CardTerminals.State.CARD_PRESENT)) {
        yubikeys.add(new UsbPcscDevice(device));
      }
    } catch (CardException e) {
      throw new RuntimeException(e);
    }
    return yubikeys;
  }
}

/*
 * Copyright (C) 2026 Yubico.
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
import com.yubico.yubikit.desktop.NfcYubiKeyDevice;
import javax.smartcardio.CardTerminal;

/**
 * A YubiKey accessed via an external NFC reader (e.g., OMNIKEY). These PC/SC terminals do NOT
 * contain "yubikey" in their name.
 */
public class NfcPcscDevice extends PcscDevice implements NfcYubiKeyDevice {

  public NfcPcscDevice(CardTerminal terminal) {
    super(terminal);
  }

  @Override
  public Transport getTransport() {
    return Transport.NFC;
  }

  @Override
  public String getFingerprint() {
    return getName(); // PC/SC terminal name, e.g. "HID Global OMNIKEY 5022"
  }
}

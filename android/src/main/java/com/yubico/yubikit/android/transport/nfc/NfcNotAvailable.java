/*
 * Copyright (C) 2019-2022 Yubico.
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

package com.yubico.yubikit.android.transport.nfc;

public class NfcNotAvailable extends Exception {
  static final long serialVersionUID = 1L;

  private final boolean disabled;

  public NfcNotAvailable(String message, boolean disabled) {
    super(message);
    this.disabled = disabled;
  }

  /**
   * If true, the NFC functionality is disabled and can be enabled. If false, the device lacks NFC
   * functionality.
   *
   * @return true if NFC is disabled
   */
  public boolean isDisabled() {
    return disabled;
  }
}

/*
 * Copyright (C) 2024-2025 Yubico.
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

package com.yubico.yubikit.core.smartcard;

import java.io.IOException;

class ApduFormatProcessor implements ApduProcessor {
  protected final SmartCardConnection connection;
  protected final ApduFormatter formatter;

  ApduFormatProcessor(SmartCardConnection connection, ApduFormatter formatter) {
    this.connection = connection;
    this.formatter = formatter;
  }

  @Override
  public ApduResponse sendApdu(Apdu apdu) throws IOException {
    byte[] data = apdu.getData();
    byte[] payload =
        formatter.formatApdu(
            apdu.getCla(),
            apdu.getIns(),
            apdu.getP1(),
            apdu.getP2(),
            data,
            0,
            data.length,
            apdu.getLe());
    return new ApduResponse(connection.sendAndReceive(payload));
  }
}

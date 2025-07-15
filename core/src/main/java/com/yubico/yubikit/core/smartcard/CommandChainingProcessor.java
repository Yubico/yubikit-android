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

package com.yubico.yubikit.core.smartcard;

import java.io.IOException;
import java.nio.ByteBuffer;

class CommandChainingProcessor extends ApduFormatProcessor {
  CommandChainingProcessor(SmartCardConnection connection, ApduFormatter formatter) {
    super(connection, formatter);
  }

  @Override
  public ApduResponse sendApdu(Apdu apdu) throws IOException {
    ByteBuffer data = ByteBuffer.wrap(apdu.getData());
    byte[] chunk = new byte[ShortApduFormatter.SHORT_APDU_MAX_CHUNK];
    while (data.remaining() > ShortApduFormatter.SHORT_APDU_MAX_CHUNK) {
      data.get(chunk);
      ApduResponse response =
          super.sendApdu(
              new Apdu(
                  (byte) (apdu.getCla() | 0x10),
                  apdu.getIns(),
                  apdu.getP1(),
                  apdu.getP2(),
                  chunk,
                  apdu.getLe()));

      if (response.getSw() != SW.OK) {
        return response;
      }
    }
    byte[] remaining = new byte[data.remaining()];
    data.get(remaining);
    return super.sendApdu(
        new Apdu(
            apdu.getCla(), apdu.getIns(), apdu.getP1(), apdu.getP2(), remaining, apdu.getLe()));
  }
}

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

import java.nio.ByteBuffer;

class ShortApduFormatter implements ApduFormatter {
  static final int SHORT_APDU_MAX_CHUNK = 0xff;

  @Override
  public byte[] formatApdu(
      byte cla, byte ins, byte p1, byte p2, byte[] data, int offset, int length, int le) {
    if (length > SHORT_APDU_MAX_CHUNK) {
      throw new IllegalArgumentException("Length must be no greater than " + SHORT_APDU_MAX_CHUNK);
    }
    if (le < 0 || le > SHORT_APDU_MAX_CHUNK) {
      throw new IllegalArgumentException("Le must be between 0 and " + SHORT_APDU_MAX_CHUNK);
    }

    ByteBuffer buf =
        ByteBuffer.allocate(
                4
                    + (length > 0 ? 1 : 0)
                    + length
                    + (le > 0 ? 1 : 0)
                    + (length == 0 && le == 0 ? 1 : 0))
            .put(cla)
            .put(ins)
            .put(p1)
            .put(p2);
    if (length > 0) {
      buf.put((byte) length).put(data, offset, length);
    }
    if (le > 0) {
      buf.put((byte) le);
    } else if (length == 0) {
      buf.put((byte) 0);
    }
    return buf.array();
  }
}

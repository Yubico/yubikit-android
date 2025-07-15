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

class ExtendedApduFormatter implements ApduFormatter {
  private final int maxApduSize;

  ExtendedApduFormatter(int maxApduSize) {
    this.maxApduSize = maxApduSize;
  }

  @Override
  public byte[] formatApdu(
      byte cla, byte ins, byte p1, byte p2, byte[] data, int offset, int length, int le) {
    ByteBuffer buf =
        ByteBuffer.allocate(5 + (data.length > 0 ? 2 : 0) + data.length + (le > 0 ? 2 : 0))
            .put(cla)
            .put(ins)
            .put(p1)
            .put(p2)
            .put((byte) 0x00);
    if (data.length > 0) {
      buf.putShort((short) data.length).put(data);
    }
    if (le > 0) {
      buf.putShort((short) le);
    }
    if (buf.limit() > maxApduSize) {
      throw new UnsupportedOperationException("APDU length exceeds YubiKey capability");
    }
    return buf.array();
  }
}

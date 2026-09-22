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

package com.yubico.yubikit.android.transport.usb.connection;

import org.jspecify.annotations.Nullable;

/**
 * The interface bytes of an ISO 7816-3 ATR (§8.2).
 *
 * <p>After TS and T0 the ATR carries TA/TB/TC/TD in fixed order, but only those the card chose to
 * send. Which ones are present is announced by the Y map in the high nibble of T0 for level 1, and
 * in the high nibble of each TD for the level after it. A missing byte means "use the ISO default",
 * which is why every accessor here is nullable rather than pre-filled: the default belongs to the
 * consumer of the field, not to the parse.
 */
final class AtrInterfaceBytes {

  /** Levels beyond 4 exist in the standard but carry nothing we act on. */
  private static final int MAX_LEVEL = 4;

  // Y-map bits in the high nibble of T0/TD, announcing the next level's bytes.
  private static final int Y_TA = 0x01;
  private static final int Y_TB = 0x02;
  private static final int Y_TC = 0x04;
  private static final int Y_TD = 0x08;

  private final @Nullable Byte[] ta = new Byte[MAX_LEVEL];
  private final @Nullable Byte[] tb = new Byte[MAX_LEVEL];
  private final @Nullable Byte[] tc = new Byte[MAX_LEVEL];

  private AtrInterfaceBytes() {}

  /** TA at {@code level} (1-based), or null if the card did not send it. */
  @Nullable Byte ta(int level) {
    return at(ta, level);
  }

  /** TB at {@code level} (1-based), or null if the card did not send it. */
  @Nullable Byte tb(int level) {
    return at(tb, level);
  }

  /** TC at {@code level} (1-based), or null if the card did not send it. */
  @Nullable Byte tc(int level) {
    return at(tc, level);
  }

  private static @Nullable Byte at(@Nullable Byte[] bytes, int level) {
    return level >= 1 && level <= MAX_LEVEL ? bytes[level - 1] : null;
  }

  /**
   * Walk an ATR and collect its interface bytes. An ATR that is absent, too short, or truncated
   * mid-walk yields whatever was read before the end - every field is optional anyway, so a partial
   * parse degrades to defaults rather than failing.
   */
  static AtrInterfaceBytes parse(byte @Nullable [] atr) {
    AtrInterfaceBytes parsed = new AtrInterfaceBytes();
    if (atr == null || atr.length < 2) {
      return parsed;
    }
    int index = 1; // skip TS, the convention byte
    int y = (atr[index++] & 0xF0) >> 4; // T0's Y map announces level 1
    int level = 1;
    while (y != 0 && level <= MAX_LEVEL && index < atr.length) {
      if ((y & Y_TA) != 0 && index < atr.length) {
        parsed.ta[level - 1] = atr[index++];
      }
      if ((y & Y_TB) != 0 && index < atr.length) {
        parsed.tb[level - 1] = atr[index++];
      }
      if ((y & Y_TC) != 0 && index < atr.length) {
        parsed.tc[level - 1] = atr[index++];
      }
      if ((y & Y_TD) != 0 && index < atr.length) {
        // TD announces the level after this one and we move on to it.
        y = (atr[index++] & 0xF0) >> 4;
        level++;
      } else {
        y = 0;
      }
    }
    return parsed;
  }
}

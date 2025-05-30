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

package com.yubico.yubikit.yubiotp;

/** Slots on YubiKey (Yubico OTP/YubiKey/Configuration interface). */
public enum Slot {
  /** Slot one (short touch of YubiKey sensor) */
  ONE,
  /** Slot two (long touch of YubiKey sensor) */
  TWO;

  /**
   * Maps a Slot value to one of two byte values.
   *
   * @param one the value to use for slot 1
   * @param two the value to use for slot 2
   * @return either one or two, depending on the slot.
   */
  byte map(byte one, byte two) {
    switch (this) {
      case ONE:
        return one;
      case TWO:
        return two;
    }
    throw new IllegalStateException("Invalid enum value");
  }
}

/*
 * Copyright (C) 2023 Yubico.
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

package com.yubico.yubikit.openpgp;

public class OpenPgpUtils {
  static byte decodeBcd(byte bcd) {
    int high = (bcd & 0xf0) >> 4;
    int low = bcd & 0x0f;
    if (high > 9 || low > 9) {
      throw new IllegalArgumentException("Invalid BCD value: " + bcd);
    }
    return (byte) (high * 10 + low);
  }
}

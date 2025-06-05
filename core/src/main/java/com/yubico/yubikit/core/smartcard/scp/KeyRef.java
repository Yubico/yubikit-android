/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.core.smartcard.scp;

import java.util.Locale;
import java.util.Objects;

/**
 * Reference to an SCP key. Each key is uniquely identified by the combination of KID and KVN.
 * Related keys typically share a KVN.
 */
public class KeyRef {
  private final byte kid;
  private final byte kvn;

  public KeyRef(byte kid, byte kvn) {
    this.kid = kid;
    this.kvn = kvn;
  }

  /**
   * @return the KID of the SCP key
   */
  public byte getKid() {
    return kid;
  }

  /**
   * @return the KVN of the SCP key.
   */
  public byte getKvn() {
    return kvn;
  }

  /**
   * @return the byte[] representation of the KID-KVN pair.
   */
  public byte[] getBytes() {
    return new byte[] {kid, kvn};
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    KeyRef keyRef = (KeyRef) o;
    return kid == keyRef.kid && kvn == keyRef.kvn;
  }

  @Override
  public int hashCode() {
    return Objects.hash(kid, kvn);
  }

  @Override
  public String toString() {
    return String.format(Locale.ROOT, "KeyRef{kid=0x%02x, kvn=0x%02x}", 0xff & kid, 0xff & kvn);
  }
}

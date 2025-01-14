/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.piv;

/** Supported management key types for use with the PIV YubiKey application. */
public enum ManagementKeyType {
  /** 3-DES (the default). */
  TDES((byte) 0x03, "DESede", 24, 8),
  /** AES-128. */
  AES128((byte) 0x08, "AES", 16, 16),
  /** AES-192. */
  AES192((byte) 0x0a, "AES", 24, 16),
  /** AES-256. */
  AES256((byte) 0x0c, "AES", 32, 16);

  public final byte value;
  public final String cipherName;
  public final int keyLength;
  public final int challengeLength;

  ManagementKeyType(byte value, String cipherName, int keyLength, int challengeLength) {
    this.value = value;
    this.cipherName = cipherName;
    this.keyLength = keyLength;
    this.challengeLength = challengeLength;
  }

  public static ManagementKeyType fromValue(byte value) {
    for (ManagementKeyType type : ManagementKeyType.values()) {
      if (type.value == value) {
        return type;
      }
    }
    throw new IllegalArgumentException("Not a valid ManagementKeyType:" + value);
  }
}

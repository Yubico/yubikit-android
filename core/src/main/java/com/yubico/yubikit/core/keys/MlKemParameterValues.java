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

package com.yubico.yubikit.core.keys;

import com.yubico.yubikit.core.util.StringUtils;
import java.util.Arrays;

/** Parameter sets for the ML-KEM key encapsulation mechanism (FIPS 203). */
public enum MlKemParameterValues {
  MLKEM_512(
      800, 768, 1632, new byte[] {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01}),
  MLKEM_768(
      1184, 1088, 2400, new byte[] {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02}),
  MLKEM_1024(
      1568, 1568, 3168, new byte[] {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03});

  /** The seed length (in bytes) is the same for all ML-KEM parameter sets. */
  public static final int SEED_LEN = 64;

  /** The shared secret length (in bytes) is the same for all ML-KEM parameter sets. */
  public static final int SHARED_SECRET_LEN = 32;

  private final int publicKeyBytes;
  private final int ciphertextBytes;
  private final int expandedPrivateKeyBytes;
  private final byte[] oid;

  MlKemParameterValues(
      int publicKeyBytes, int ciphertextBytes, int expandedPrivateKeyBytes, byte[] oid) {
    this.publicKeyBytes = publicKeyBytes;
    this.ciphertextBytes = ciphertextBytes;
    this.expandedPrivateKeyBytes = expandedPrivateKeyBytes;
    this.oid = oid;
  }

  /** Returns the length (in bytes) of an encoded ML-KEM public key for this parameter set. */
  public int getPublicKeyLength() {
    return publicKeyBytes;
  }

  /** Returns the length (in bytes) of an ML-KEM ciphertext for this parameter set. */
  public int getCiphertextLength() {
    return ciphertextBytes;
  }

  /** Returns the length (in bytes) of the private key seed for this parameter set. */
  public int getSeedLength() {
    return SEED_LEN;
  }

  /** Returns the length (in bytes) of the expanded private key for this parameter set. */
  public int getExpandedPrivateKeyLength() {
    return expandedPrivateKeyBytes;
  }

  byte[] getOid() {
    return Arrays.copyOf(oid, oid.length);
  }

  @Override
  public String toString() {
    return "MlKemParameterValues{"
        + "name="
        + name()
        + ", oid="
        + StringUtils.bytesToHex(oid)
        + '}';
  }

  public static MlKemParameterValues fromOid(byte[] oid) {
    for (MlKemParameterValues match : MlKemParameterValues.values()) {
      if (Arrays.equals(oid, match.oid)) {
        return match;
      }
    }
    throw new IllegalArgumentException("Not a supported ML-KEM parameter set");
  }
}

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

/** Parameter sets for the ML-DSA digital signature algorithm (FIPS 204). */
public enum MlDsaParameterValues {
  MLDSA_44(
      128,
      1312,
      2420,
      2560,
      new byte[] {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11}),
  MLDSA_65(
      192,
      1952,
      3309,
      4032,
      new byte[] {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}),
  MLDSA_87(
      256,
      2592,
      4627,
      4896,
      new byte[] {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13});

  /** The seed length (in bytes) is the same for all ML-DSA parameter sets. */
  public static final int SEED_LEN = 32;

  private final int securityStrength;
  private final int publicKeyBytes;
  private final int signatureBytes;
  private final int expandedPrivateKeyBytes;
  private final byte[] oid;

  MlDsaParameterValues(
      int securityStrength,
      int publicKeyBytes,
      int signatureBytes,
      int expandedPrivateKeyBytes,
      byte[] oid) {
    this.securityStrength = securityStrength;
    this.publicKeyBytes = publicKeyBytes;
    this.signatureBytes = signatureBytes;
    this.expandedPrivateKeyBytes = expandedPrivateKeyBytes;
    this.oid = oid;
  }

  /** Returns the NIST security strength (in bits) claimed by this parameter set. */
  public int getSecurityStrength() {
    return securityStrength;
  }

  /** Returns the length (in bytes) of an encoded ML-DSA public key for this parameter set. */
  public int getPublicKeyLength() {
    return publicKeyBytes;
  }

  /** Returns the length (in bytes) of an ML-DSA signature for this parameter set. */
  public int getSignatureLength() {
    return signatureBytes;
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
    return "MlDsaParameterValues{"
        + "name="
        + name()
        + ", securityStrength="
        + securityStrength
        + ", oid="
        + StringUtils.bytesToHex(oid)
        + '}';
  }

  public static MlDsaParameterValues fromOid(byte[] oid) {
    for (MlDsaParameterValues match : MlDsaParameterValues.values()) {
      if (Arrays.equals(oid, match.oid)) {
        return match;
      }
    }
    throw new IllegalArgumentException("Not a supported ML-DSA parameter set");
  }
}

/*
 * Copyright (C) 2019-2022,2024 Yubico.
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

/**
 * The verification policy of a private key defines the required verification to use the key.
 *
 * <p>Setting a verification policy other than DEFAULT requires YubiKey 4 or later.
 */
public enum VerificationPolicy {
  /** The default behavior for the particular key slot is used. */
  DEFAULT(0x0),

  /** The PIN is never required for using the key. */
  NEVER(0x1),

  /** The PIN must be verified for the session, prior to using the key. */
  ONCE(0x2),

  /** The PIN must be verified each time the key is to be used, just prior to using it. */
  ALWAYS(0x3),

  /** PIN or biometrics must be verified for the session, prior to using the key. */
  MATCH_ONCE(0x4),

  /** PIN or biometrics must be verified each time the key is to be used, just prior to using it. */
  MATCH_ALWAYS(0x5);

  public final int value;

  VerificationPolicy(int value) {
    this.value = value;
  }

  /** Returns the PIN policy corresponding to the given PIV application constant. */
  public static VerificationPolicy fromValue(int value) {
    if (value >= 0 && value < VerificationPolicy.values().length) {
      return VerificationPolicy.values()[value];
    }
    throw new IllegalArgumentException("Not a valid VerificationPolicy :" + value);
  }
}

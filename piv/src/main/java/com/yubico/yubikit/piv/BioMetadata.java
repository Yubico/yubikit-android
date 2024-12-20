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

package com.yubico.yubikit.piv;

public class BioMetadata {
  private final boolean configured;
  private final int attemptsRemaining;
  private final boolean temporaryPin;

  public BioMetadata(boolean configured, int attemptsRemaining, boolean temporaryPin) {
    this.configured = configured;
    this.attemptsRemaining = attemptsRemaining;
    this.temporaryPin = temporaryPin;
  }

  /**
   * Indicates whether biometrics are configured or not (fingerprints enrolled or not).
   *
   * <p>A false return value indicates a YubiKey Bio without biometrics configured and hence the
   * client should fallback to a PIN based authentication.
   *
   * @return true if biometrics are configured or not.
   */
  public boolean isConfigured() {
    return configured;
  }

  /**
   * Returns value of biometric match retry counter which states how many biometric match retries
   * are left until a YubiKey Bio is blocked.
   *
   * <p>If this method returns 0 and {@link #isConfigured()} returns true, the device is blocked for
   * biometric match and the client should invoke PIN based authentication to reset the biometric
   * match retry counter.
   */
  public int getAttemptsRemaining() {
    return attemptsRemaining;
  }

  /**
   * Indicates whether a temporary PIN has been generated in the YubiKey in relation to a successful
   * biometric match.
   *
   * @return true if a temporary PIN has been generated.
   */
  public boolean hasTemporaryPin() {
    return temporaryPin;
  }
}

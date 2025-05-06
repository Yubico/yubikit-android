/*
 * Copyright (C) 2024-2025 Yubico.
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

package com.yubico.yubikit.core.application;

import com.yubico.yubikit.core.Version;
import javax.annotation.Nullable;

/**
 * Adds support for overriding YubiKey session version number.
 *
 * <p>Internal use only.
 */
public class SessionVersionOverride {

  @Nullable private static Version versionOverride = null;
  private static final Version developmentVersion = new Version(0, 0, 1);

  /**
   * Internal use only.
   *
   * <p>Override version of connected YubiKey with the specified version.
   *
   * @param overrideVersion version which will be used instead of development versions.
   */
  public static void set(@Nullable Version overrideVersion) {
    versionOverride = overrideVersion;
  }

  /**
   * Returns an applicable override of version.
   *
   * @param version The version which might be overridden.
   * @return Version to use.
   */
  public static Version overrideOf(Version version) {
    return (versionOverride != null && isDevelopmentVersion(version)) ? versionOverride : version;
  }

  /** return true if this is ALPHA or BETA version */
  public static boolean isDevelopmentVersion(Version version) {
    return version.equals(developmentVersion);
  }
}

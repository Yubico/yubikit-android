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

package com.yubico.yubikit.fido.client.extensions;

import java.net.URI;

/**
 * Shared validation helpers for the legacy U2F {@code appid} and {@code appidExclude} extensions.
 *
 * <p>Both extensions apply identical validation to their AppID input, so the logic lives here to
 * keep the two paths from drifting.
 */
final class AppIdValidation {

  private AppIdValidation() {}

  /** Returns true if the AppID is a well-formed HTTPS URL with a host component. */
  static boolean isValidHttpsAppId(String appId) {
    try {
      URI uri = new URI(appId);
      return "https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null;
    } catch (Exception e) {
      return false;
    }
  }
}

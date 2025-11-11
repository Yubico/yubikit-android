/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.fido.client;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {

  /**
   * Return SHA-256 hash of the provided input
   *
   * @param message The hash input
   * @return SHA-256 of the input
   */
  public static byte[] hash(byte[] message) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(message);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}

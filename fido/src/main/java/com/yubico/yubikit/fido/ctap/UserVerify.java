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

package com.yubico.yubikit.fido.ctap;

import java.util.Locale;

/**
 * The USER_VERIFY constants are flags in a bitfield represented as a 32 bit long integer. They
 * describe the methods and capabilities of a FIDO authenticator for locally verifying a user.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">User
 *     Verification Methods</a>
 */
public enum UserVerify {
  UNDEFINED(0x0),
  PRESENCE_INTERNAL(0x00000001),
  FINGERPRINT_INTERNAL(0x00000002),
  PASSCODE_INTERNAL(0x00000004),
  VOICEPRINT_INTERNAL(0x00000008),
  FACEPRINT_INTERNAL(0x00000010),
  LOCATION_INTERNAL(0x00000020),
  EYEPRINT_INTERNAL(0x00000040),
  PATTERN_INTERNAL(0x00000080),
  HANDPRINT_INTERNAL(0x00000100),
  PASSCODE_EXTERNAL(0x00000800),
  PATTERN_EXTERNAL(0x00001000),
  NONE(0x00000200),
  ALL(0x00000400);

  public final int value;
  public final String name;

  UserVerify(int value) {
    this.value = value;
    this.name = this.name().toLowerCase(Locale.ROOT);
  }
}

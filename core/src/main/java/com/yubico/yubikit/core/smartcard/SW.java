/*
 * Copyright (C) 2020-2022,2024 Yubico.
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
package com.yubico.yubikit.core.smartcard;

/** Contains constants for APDU status codes (SW1, SW2). */
public final class SW {
  public static final short NO_INPUT_DATA = 0x6285;
  public static final short VERIFY_FAIL_NO_RETRY = 0x63C0;
  public static final short MEMORY_ERROR = 0x6581;
  public static final short WRONG_LENGTH = 0x6700;
  public static final short SECURITY_CONDITION_NOT_SATISFIED = 0x6982;
  public static final short AUTH_METHOD_BLOCKED = 0x6983;
  public static final short DATA_INVALID = 0x6984;
  public static final short CONDITIONS_NOT_SATISFIED = 0x6985;
  public static final short COMMAND_NOT_ALLOWED = 0x6986;
  public static final short INCORRECT_PARAMETERS = 0x6A80;
  public static final short FILE_NOT_FOUND = 0x6A82;
  public static final short NO_SPACE = 0x6A84;
  public static final short REFERENCED_DATA_NOT_FOUND = 0x6A88;
  public static final short WRONG_PARAMETERS_P1P2 = 0x6B00;
  public static final short INVALID_INSTRUCTION = 0x6D00;
  public static final short CLASS_NOT_SUPPORTED = 0x6E00;
  public static final short COMMAND_ABORTED = 0x6F00;
  public static final short OK = (short) 0x9000;

  private SW() {
    throw new IllegalStateException();
  }
}

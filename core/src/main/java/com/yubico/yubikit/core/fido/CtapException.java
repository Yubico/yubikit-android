/*
 * Copyright (C) 2020-2024 Yubico.
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
package com.yubico.yubikit.core.fido;

import com.yubico.yubikit.core.application.CommandException;
import java.util.Locale;

/**
 * An error on the CTAP-level, returned from the Authenticator.
 *
 * <p>These error codes are defined by the <a
 * href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#error-responses">CTAP2
 * specification</a>
 */
public class CtapException extends CommandException {
  public static final byte ERR_SUCCESS = 0x00;
  public static final byte ERR_INVALID_COMMAND = 0x01;
  public static final byte ERR_INVALID_PARAMETER = 0x02;
  public static final byte ERR_INVALID_LENGTH = 0x03;
  public static final byte ERR_INVALID_SEQ = 0x04;
  public static final byte ERR_TIMEOUT = 0x05;
  public static final byte ERR_CHANNEL_BUSY = 0x06;
  public static final byte ERR_LOCK_REQUIRED = 0x0A;
  public static final byte ERR_INVALID_CHANNEL = 0x0B;
  public static final byte ERR_CBOR_UNEXPECTED_TYPE = 0x11;
  public static final byte ERR_INVALID_CBOR = 0x12;
  public static final byte ERR_MISSING_PARAMETER = 0x14;
  public static final byte ERR_LIMIT_EXCEEDED = 0x15;
  public static final byte ERR_UNSUPPORTED_EXTENSION = 0x16;
  public static final byte ERR_FP_DATABASE_FULL = 0x17;
  public static final byte ERR_LARGE_BLOB_STORAGE_FULL = 0x18;
  public static final byte ERR_CREDENTIAL_EXCLUDED = 0x19;
  public static final byte ERR_PROCESSING = 0x21;
  public static final byte ERR_INVALID_CREDENTIAL = 0x22;
  public static final byte ERR_USER_ACTION_PENDING = 0x23;
  public static final byte ERR_OPERATION_PENDING = 0x24;
  public static final byte ERR_NO_OPERATIONS = 0x25;
  public static final byte ERR_UNSUPPORTED_ALGORITHM = 0x26;
  public static final byte ERR_OPERATION_DENIED = 0x27;
  public static final byte ERR_KEY_STORE_FULL = 0x28;
  public static final byte ERR_NOT_BUSY = 0x29;
  public static final byte ERR_NO_OPERATION_PENDING = 0x2A;
  public static final byte ERR_UNSUPPORTED_OPTION = 0x2B;
  public static final byte ERR_INVALID_OPTION = 0x2C;
  public static final byte ERR_KEEPALIVE_CANCEL = 0x2D;
  public static final byte ERR_NO_CREDENTIALS = 0x2E;
  public static final byte ERR_USER_ACTION_TIMEOUT = 0x2F;
  public static final byte ERR_NOT_ALLOWED = 0x30;
  public static final byte ERR_PIN_INVALID = 0x31;
  public static final byte ERR_PIN_BLOCKED = 0x32;
  public static final byte ERR_PIN_AUTH_INVALID = 0x33;
  public static final byte ERR_PIN_AUTH_BLOCKED = 0x34;
  public static final byte ERR_PIN_NOT_SET = 0x35;
  @Deprecated // use ERR_PUAT_REQUIRED
  public static final byte ERR_PIN_REQUIRED = 0x36;
  public static final byte ERR_PUAT_REQUIRED = 0x36; // CTAP2.1 naming
  public static final byte ERR_PIN_POLICY_VIOLATION = 0x37;
  public static final byte ERR_PIN_TOKEN_EXPIRED = 0x38;
  public static final byte ERR_REQUEST_TOO_LARGE = 0x39;
  public static final byte ERR_ACTION_TIMEOUT = 0x3A;
  public static final byte ERR_UP_REQUIRED = 0x3B;
  public static final byte ERR_UV_BLOCKED = 0x3C;
  public static final byte ERR_INTEGRITY_FAILURE = 0x3D;
  public static final byte ERR_INVALID_SUBCOMMAND = 0x3E;
  public static final byte ERR_UV_INVALID = 0x3F;
  public static final byte ERR_UNAUTHORIZED_PERMISSION = 0x40;
  public static final byte ERR_OTHER = 0x7F;
  public static final byte ERR_SPEC_LAST = (byte) 0xDF;
  public static final byte ERR_EXTENSION_FIRST = (byte) 0xE0;
  public static final byte ERR_EXTENSION_LAST = (byte) 0xEF;
  public static final byte ERR_VENDOR_FIRST = (byte) 0xF0;
  public static final byte ERR_VENDOR_LAST = (byte) 0xFF;

  private final byte ctapError;

  public CtapException(byte ctapError) {
    super(String.format(Locale.ROOT, "CTAP error: 0x%02x", ctapError));

    this.ctapError = ctapError;
  }

  public byte getCtapError() {
    return ctapError;
  }
}

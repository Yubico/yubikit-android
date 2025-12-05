/*
 * Copyright (C) 2020-2025 Yubico.
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

import static java.util.Collections.unmodifiableMap;

import com.yubico.yubikit.core.application.CommandException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * An error on the CTAP-level, returned from the Authenticator.
 *
 * <p>These error codes are defined by the <a
 * href="https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#error-responses">CTAP2
 * Status codes</a>
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
  public static final byte ERR_PUAT_REQUIRED = 0x36;
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

  private static final Map<Byte, String> ERROR_NAMES = createErrorNamesMap();

  private final byte ctapError;

  /**
   * Constructs a new CtapException with the specified CTAP error code.
   *
   * @param ctapError the CTAP error code returned from the authenticator
   */
  public CtapException(byte ctapError) {
    super(
        String.format(Locale.ROOT, "CTAP error: %s (0x%02x)", getErrorName(ctapError), ctapError));

    this.ctapError = ctapError;
  }

  /**
   * Returns the CTAP error code associated with this exception.
   *
   * @return the CTAP error code
   */
  public byte getCtapError() {
    return ctapError;
  }

  /**
   * Returns the name of the CTAP error associated with this exception.
   *
   * @return the CTAP error name as a String
   */
  public String getErrorName() {
    return getErrorName(ctapError);
  }

  private static String getErrorName(byte error) {
    String name = ERROR_NAMES.get(error);
    if (name != null) {
      return name;
    }

    int errorUnsigned = error & 0xFF;
    if (errorUnsigned >= (ERR_EXTENSION_FIRST & 0xFF)
        && errorUnsigned <= (ERR_EXTENSION_LAST & 0xFF)) {
      return "EXTENSION_ERROR";
    } else if (errorUnsigned >= (ERR_VENDOR_FIRST & 0xFF)) {
      return "VENDOR_ERROR";
    } else {
      // Unknown error within spec range (0x00-0xDF)
      return "UNKNOWN";
    }
  }

  private static Map<Byte, String> createErrorNamesMap() {
    Map<Byte, String> map = new HashMap<>();
    map.put(ERR_SUCCESS, "SUCCESS");
    map.put(ERR_INVALID_COMMAND, "INVALID_COMMAND");
    map.put(ERR_INVALID_PARAMETER, "INVALID_PARAMETER");
    map.put(ERR_INVALID_LENGTH, "INVALID_LENGTH");
    map.put(ERR_INVALID_SEQ, "INVALID_SEQ");
    map.put(ERR_TIMEOUT, "TIMEOUT");
    map.put(ERR_CHANNEL_BUSY, "CHANNEL_BUSY");
    map.put(ERR_LOCK_REQUIRED, "LOCK_REQUIRED");
    map.put(ERR_INVALID_CHANNEL, "INVALID_CHANNEL");
    map.put(ERR_CBOR_UNEXPECTED_TYPE, "CBOR_UNEXPECTED_TYPE");
    map.put(ERR_INVALID_CBOR, "INVALID_CBOR");
    map.put(ERR_MISSING_PARAMETER, "MISSING_PARAMETER");
    map.put(ERR_LIMIT_EXCEEDED, "LIMIT_EXCEEDED");
    map.put(ERR_UNSUPPORTED_EXTENSION, "UNSUPPORTED_EXTENSION");
    map.put(ERR_FP_DATABASE_FULL, "FP_DATABASE_FULL");
    map.put(ERR_LARGE_BLOB_STORAGE_FULL, "LARGE_BLOB_STORAGE_FULL");
    map.put(ERR_CREDENTIAL_EXCLUDED, "CREDENTIAL_EXCLUDED");
    map.put(ERR_PROCESSING, "PROCESSING");
    map.put(ERR_INVALID_CREDENTIAL, "INVALID_CREDENTIAL");
    map.put(ERR_USER_ACTION_PENDING, "USER_ACTION_PENDING");
    map.put(ERR_OPERATION_PENDING, "OPERATION_PENDING");
    map.put(ERR_NO_OPERATIONS, "NO_OPERATIONS");
    map.put(ERR_UNSUPPORTED_ALGORITHM, "UNSUPPORTED_ALGORITHM");
    map.put(ERR_OPERATION_DENIED, "OPERATION_DENIED");
    map.put(ERR_KEY_STORE_FULL, "KEY_STORE_FULL");
    map.put(ERR_NOT_BUSY, "NOT_BUSY");
    map.put(ERR_NO_OPERATION_PENDING, "NO_OPERATION_PENDING");
    map.put(ERR_UNSUPPORTED_OPTION, "UNSUPPORTED_OPTION");
    map.put(ERR_INVALID_OPTION, "INVALID_OPTION");
    map.put(ERR_KEEPALIVE_CANCEL, "KEEPALIVE_CANCEL");
    map.put(ERR_NO_CREDENTIALS, "NO_CREDENTIALS");
    map.put(ERR_USER_ACTION_TIMEOUT, "USER_ACTION_TIMEOUT");
    map.put(ERR_NOT_ALLOWED, "NOT_ALLOWED");
    map.put(ERR_PIN_INVALID, "PIN_INVALID");
    map.put(ERR_PIN_BLOCKED, "PIN_BLOCKED");
    map.put(ERR_PIN_AUTH_INVALID, "PIN_AUTH_INVALID");
    map.put(ERR_PIN_AUTH_BLOCKED, "PIN_AUTH_BLOCKED");
    map.put(ERR_PIN_NOT_SET, "PIN_NOT_SET");
    map.put(ERR_PUAT_REQUIRED, "PUAT_REQUIRED");
    map.put(ERR_PIN_POLICY_VIOLATION, "PIN_POLICY_VIOLATION");
    map.put(ERR_PIN_TOKEN_EXPIRED, "PIN_TOKEN_EXPIRED");
    map.put(ERR_REQUEST_TOO_LARGE, "REQUEST_TOO_LARGE");
    map.put(ERR_ACTION_TIMEOUT, "ACTION_TIMEOUT");
    map.put(ERR_UP_REQUIRED, "UP_REQUIRED");
    map.put(ERR_UV_BLOCKED, "UV_BLOCKED");
    map.put(ERR_INTEGRITY_FAILURE, "INTEGRITY_FAILURE");
    map.put(ERR_INVALID_SUBCOMMAND, "INVALID_SUBCOMMAND");
    map.put(ERR_UV_INVALID, "UV_INVALID");
    map.put(ERR_UNAUTHORIZED_PERMISSION, "UNAUTHORIZED_PERMISSION");
    map.put(ERR_OTHER, "OTHER");
    return unmodifiableMap(map);
  }
}

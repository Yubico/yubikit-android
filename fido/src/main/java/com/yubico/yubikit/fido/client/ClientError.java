/*
 * Copyright (C) 2020-2023 Yubico.
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

import com.yubico.yubikit.core.fido.CtapException;
import java.util.Locale;

/** An error thrown by the WebAuthn client upon failure to complete a command. */
public class ClientError extends Exception {
  private static final long serialVersionUID = 1L;

  /** Client error types */
  public enum Code {
    OTHER_ERROR(1),
    BAD_REQUEST(2),
    CONFIGURATION_UNSUPPORTED(3),
    DEVICE_INELIGIBLE(4),
    TIMEOUT(5);

    private final int errorCode;

    Code(int errorCode) {
      this.errorCode = errorCode;
    }

    @SuppressWarnings("unused")
    public int getErrorCode() {
      return errorCode;
    }

    @Override
    public String toString() {
      return String.format(Locale.ROOT, "%s (code %d)", name(), errorCode);
    }
  }

  private final Code errorCode;

  public ClientError(Code errorCode, String message) {
    super(errorCode + " - " + message);
    this.errorCode = errorCode;
  }

  public ClientError(Code errorCode, Throwable cause) {
    super(errorCode.toString(), cause);
    this.errorCode = errorCode;
  }

  @SuppressWarnings("unused")
  public Code getErrorCode() {
    return errorCode;
  }

  /**
   * Translate CTAP errors into client errors
   *
   * @param error CTAP Error
   * @return The equivalent ClientError
   */
  static ClientError wrapCtapException(CtapException error) {
    switch (error.getCtapError()) {
      case CtapException.ERR_CREDENTIAL_EXCLUDED:
      case CtapException.ERR_NO_CREDENTIALS:
        return new ClientError(Code.DEVICE_INELIGIBLE, error);
      case CtapException.ERR_TIMEOUT:
      case CtapException.ERR_KEEPALIVE_CANCEL:
      case CtapException.ERR_ACTION_TIMEOUT:
      case CtapException.ERR_USER_ACTION_TIMEOUT:
        return new ClientError(Code.TIMEOUT, error);
      case CtapException.ERR_UNSUPPORTED_ALGORITHM:
      case CtapException.ERR_UNSUPPORTED_OPTION:
      case CtapException.ERR_UNSUPPORTED_EXTENSION:
      case CtapException.ERR_KEY_STORE_FULL:
        return new ClientError(Code.CONFIGURATION_UNSUPPORTED, error);
      case CtapException.ERR_INVALID_COMMAND:
      case CtapException.ERR_CBOR_UNEXPECTED_TYPE:
      case CtapException.ERR_INVALID_CBOR:
      case CtapException.ERR_MISSING_PARAMETER:
      case CtapException.ERR_INVALID_OPTION:
      case CtapException.ERR_PUAT_REQUIRED:
      case CtapException.ERR_PIN_INVALID:
      case CtapException.ERR_PIN_BLOCKED:
      case CtapException.ERR_PIN_NOT_SET:
      case CtapException.ERR_PIN_POLICY_VIOLATION:
      case CtapException.ERR_PIN_TOKEN_EXPIRED:
      case CtapException.ERR_PIN_AUTH_INVALID:
      case CtapException.ERR_PIN_AUTH_BLOCKED:
      case CtapException.ERR_UV_BLOCKED:
      case CtapException.ERR_UV_INVALID:
      case CtapException.ERR_REQUEST_TOO_LARGE:
      case CtapException.ERR_OPERATION_DENIED:
        return new ClientError(Code.BAD_REQUEST, error);
      default:
        return new ClientError(Code.OTHER_ERROR, error);
    }
  }
}

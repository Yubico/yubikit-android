/*
 * Copyright (C) 2019-2025 Yubico.
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

import com.yubico.yubikit.core.application.CommandException;
import java.util.Locale;

/**
 * Thrown when an APDU command fails with an error code. See {@link SW} for a list of status codes.
 */
public class ApduException extends CommandException {
  private static final long serialVersionUID = 1L;

  private final short sw;
  private final byte[] data;

  @Deprecated
  public ApduException(short sw) {
    this(sw, String.format(Locale.ROOT, "APDU error: 0x%04x", sw));
  }

  @Deprecated
  public ApduException(short sw, String message) {
    super(message);
    this.sw = sw;
    this.data = new byte[0];
  }

  public ApduException(byte[] data, short sw) {
    this(data, sw, String.format(Locale.ROOT, "APDU error: 0x%04x", sw));
  }

  public ApduException(byte[] data, short sw, String message) {
    super(message);
    this.sw = sw;
    this.data = data;
  }

  /**
   * Gets error code that received via APDU response
   *
   * @return error code
   */
  public short getSw() {
    return sw;
  }

  /**
   * Gets the data received via APDU response
   *
   * @return response data
   */
  public byte[] getData() {
    return data;
  }
}

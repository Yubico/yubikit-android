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

package com.yubico.yubikit.fido.client;

import com.yubico.yubikit.core.fido.CtapException;

/**
 * A subclass of {@link ClientError} used by {@link BasicWebAuthnClient} to indicate that
 * makeCredential or getAssertion was called with invalid authentication (PIN or UV).
 */
public class AuthInvalidClientError extends ClientError {

  public enum AuthType {
    PIN,
    UV
  }

  public final AuthType authType;
  public final int retries;

  /**
   * @param authType type of authentication (PIN or UV)
   * @param retries number of retries left before the authenticator is blocked
   */
  public AuthInvalidClientError(CtapException cause, AuthType authType, int retries) {
    super(Code.BAD_REQUEST, cause);
    this.authType = authType;
    this.retries = retries;
  }
}

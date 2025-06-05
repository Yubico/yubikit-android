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

/**
 * A subclass of {@link ClientError} used by {@link BasicWebAuthnClient} to indicate that
 * makeCredential or getAssertion was called with an invalid PIN.
 */
public class PinInvalidClientError extends ClientError {

  public final int pinRetries;

  /**
   * @param pinRetries number of retries left before the authenticator is blocked
   */
  public PinInvalidClientError(CtapException cause, int pinRetries) {
    super(Code.BAD_REQUEST, cause);
    this.pinRetries = pinRetries;
  }
}

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

/**
 * A subclass of {@link ClientError} used by {@link BasicWebAuthnClient} to indicate that
 * makeCredential or getAssertion was called without a PIN even though a PIN is required to complete
 * the operation. Client implementations may want to catch this and handle it differently than other
 * ClientErrors.
 */
public class PinRequiredClientError extends ClientError {
  public PinRequiredClientError() {
    super(Code.BAD_REQUEST, "PIN required but not provided");
  }
}

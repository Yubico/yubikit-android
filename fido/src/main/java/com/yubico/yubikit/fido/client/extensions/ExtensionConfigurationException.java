/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit.fido.client.extensions;

import com.yubico.yubikit.fido.client.ClientError;

/**
 * Thrown by an {@link Extension} when the relying party has explicitly requested a capability that
 * cannot be satisfied (for example {@code enforceCredentialProtectionPolicy} or {@code largeBlob}
 * {@code support: "required"} on an authenticator that does not support it).
 *
 * <p>Unlike conditions that merely cause an extension to be ignored — which are signalled by
 * returning {@code null} from the extension's processing methods — this is a <em>hard failure</em>
 * that must abort the WebAuthn ceremony. The client catches it and surfaces it as a {@link
 * ClientError} with the carried {@link ClientError.Code}.
 *
 * <p>It is unchecked so it can be raised from the extension processing lambdas (whose functional
 * interfaces do not declare checked exceptions) without changing the {@link Extension} API.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">WebAuthn Extensions</a>
 */
public class ExtensionConfigurationException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  private final ClientError.Code code;

  public ExtensionConfigurationException(String message) {
    this(ClientError.Code.CONFIGURATION_UNSUPPORTED, message);
  }

  public ExtensionConfigurationException(ClientError.Code code, String message) {
    super(message);
    this.code = code;
  }

  /** The {@link ClientError.Code} the client should report when aborting the ceremony. */
  public ClientError.Code getCode() {
    return code;
  }
}

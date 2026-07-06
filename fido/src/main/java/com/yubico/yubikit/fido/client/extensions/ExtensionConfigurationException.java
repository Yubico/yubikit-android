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
 * Thrown by an {@link Extension} when a relying-party extension request cannot be processed and the
 * WebAuthn ceremony must be aborted — for example an unsatisfiable request shape ({@code largeBlob}
 * {@code write} with more than one allowed credential) or malformed extension input.
 *
 * <p>Unlike conditions that merely cause an extension to be ignored — which are signalled by
 * returning {@code null} from the extension's processing methods — this is a <em>hard failure</em>.
 * The client catches it and surfaces it as a {@link ClientError} carrying {@link #getCode()}, with
 * this exception preserved as the {@code ClientError} cause.
 *
 * <p>This is the common supertype for every extension hard failure, so a caller can test for "an
 * extension request failed" with a single {@code instanceof} check. The one case that needs to be
 * distinguished — the authenticator lacking a capability the relying party explicitly required — is
 * the subtype {@link ExtensionNotSupportedException}; everything else (request-shape and malformed
 * input, told apart by {@link #getCode()}: {@link ClientError.Code#CONFIGURATION_UNSUPPORTED} ≙
 * {@code NotSupportedError}, {@link ClientError.Code#BAD_REQUEST} ≙ {@code SyntaxError}) carries
 * its human-readable detail in the message.
 *
 * <p>It is unchecked so it can be raised from the extension processing lambdas (whose functional
 * interfaces do not declare checked exceptions) without changing the {@link Extension} API.
 *
 * @see ExtensionNotSupportedException
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

  public ExtensionConfigurationException(ClientError.Code code, String message, Throwable cause) {
    super(message, cause);
    this.code = code;
  }

  /** The {@link ClientError.Code} the client should report when aborting the ceremony. */
  public ClientError.Code getCode() {
    return code;
  }

  /**
   * The WebAuthn {@code DOMException} name a client should reject the ceremony with for this
   * failure: {@code "SyntaxError"} for {@link ClientError.Code#BAD_REQUEST} (malformed input),
   * {@code "NotSupportedError"} otherwise (an unsatisfiable/unsupported request). Kept here, next
   * to {@link #getCode()}, so the {@code Code}-to-spec-name mapping lives in one place rather than
   * being re-derived by each caller.
   */
  public String getWebAuthnErrorName() {
    return code == ClientError.Code.BAD_REQUEST ? "SyntaxError" : "NotSupportedError";
  }
}

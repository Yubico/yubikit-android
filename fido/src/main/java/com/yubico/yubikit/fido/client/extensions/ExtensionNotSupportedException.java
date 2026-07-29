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
 * Raised when the relying party explicitly <em>required</em> an extension capability that this
 * authenticator does not support, so the ceremony must abort — currently {@code credProtect} with
 * {@code enforceCredentialProtectionPolicy}, and {@code largeBlob} {@code support: "required"} on a
 * key without large-blob storage.
 *
 * <p>This is the one extension hard failure that means "this authenticator is ineligible for the
 * request" rather than "the request itself is malformed/unsatisfiable". It is a distinct type (not
 * a flag on {@link ExtensionConfigurationException}) so a caller can react to it — e.g. tell the
 * user their security key can't be used for this site — with a plain {@code instanceof} check,
 * without inspecting messages. All other extension failures are the base {@link
 * ExtensionConfigurationException}; a caller that does not care about the distinction can catch the
 * supertype and treat every extension failure uniformly.
 *
 * <p>Note this is a WebAuthn {@code NotSupportedError} (hence {@link
 * ClientError.Code#CONFIGURATION_UNSUPPORTED}); the "ineligible" framing is a client/UI concern,
 * not a change to the spec error class.
 *
 * @see ExtensionConfigurationException
 */
public class ExtensionNotSupportedException extends ExtensionConfigurationException {
  private static final long serialVersionUID = 1L;

  public ExtensionNotSupportedException(String message) {
    super(ClientError.Code.CONFIGURATION_UNSUPPORTED, message);
  }
}

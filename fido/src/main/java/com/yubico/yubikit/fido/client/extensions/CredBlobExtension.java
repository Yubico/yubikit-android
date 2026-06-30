/*
 * Copyright (C) 2024-2026 Yubico.
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

import static com.yubico.yubikit.core.internal.codec.Base64.fromUrlSafeString;

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import java.util.Collections;
import org.jspecify.annotations.Nullable;

/**
 * Implements the Credential Blob (credBlob) CTAP2 extension.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-credBlob-extension">Credential
 *     Blob (credBlob)</a>
 */
public class CredBlobExtension extends Extension {

  public CredBlobExtension() {
    super("credBlob");
  }

  @Nullable
  @Override
  public RegistrationProcessor makeCredential(
      Ctap2Session ctap,
      PublicKeyCredentialCreationOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {

    if (!isSupported(ctap)) {
      return null;
    }

    Extensions extensions = options.getExtensions();
    if (extensions == null) {
      return null;
    }

    Object value = extensions.get("credBlob");
    if (value == null) {
      return null; // not requested
    }
    if (!(value instanceof String)) {
      throw new IllegalArgumentException("credBlob must be a string");
    }
    byte[] blob = fromUrlSafeString((String) value);
    // Per spec, the platform passes credBlob to the authenticator only when it fits within
    // maxCredBlobLength; otherwise it is ignored.
    if (blob.length <= ctap.getCachedInfo().getMaxCredBlobLength()) {
      return new RegistrationProcessor(pinToken -> Collections.singletonMap(name, blob));
    }

    return null;
  }

  @Nullable
  @Override
  public AuthenticationProcessor getAssertion(
      Ctap2Session ctap,
      PublicKeyCredentialRequestOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {

    Extensions extensions = options.getExtensions();
    if (extensions == null) {
      return null;
    }
    Object getCredBlob = extensions.get("getCredBlob");
    if (getCredBlob != null && !(getCredBlob instanceof Boolean)) {
      throw new IllegalArgumentException("getCredBlob must be a boolean");
    }
    if (isSupported(ctap) && Boolean.TRUE.equals(getCredBlob)) {
      return new AuthenticationProcessor(
          (AuthenticationInput) (selected, pinToken) -> Collections.singletonMap(name, true));
    }
    return null;
  }
}

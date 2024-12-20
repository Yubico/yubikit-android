/*
 * Copyright (C) 2024 Yubico.
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
import javax.annotation.Nullable;

/**
 * Implements the Credential Blob (credBlob) CTAP2 extension.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-credBlob-extension">Credential
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

    String b64Blob = (String) extensions.get("credBlob");
    if (b64Blob != null) {
      byte[] blob = fromUrlSafeString(b64Blob);
      if (blob.length <= ctap.getCachedInfo().getMaxCredBlobLength()) {
        return new RegistrationProcessor(pinToken -> Collections.singletonMap(name, blob));
      }
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
    if (isSupported(ctap) && Boolean.TRUE.equals(extensions.get("getCredBlob"))) {
      return new AuthenticationProcessor(
          (AuthenticationInput) (selected, pinToken) -> Collections.singletonMap(name, true));
    }
    return null;
  }
}

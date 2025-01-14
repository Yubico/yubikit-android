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

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import java.util.Collections;
import javax.annotation.Nullable;

/**
 * Implements the Credential Properties (credProps) WebAuthn extension.
 *
 * @see <a
 *     href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension">Credential
 *     Properties Extension (credProps)</a>
 */
public class CredPropsExtension extends Extension {

  public CredPropsExtension() {
    super("credProps");
  }

  @Nullable
  @Override
  public RegistrationProcessor makeCredential(
      Ctap2Session ctap,
      PublicKeyCredentialCreationOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {

    Extensions extensions = options.getExtensions();
    if (extensions == null) {
      return null;
    }

    if (extensions.has(name)) {
      AuthenticatorSelectionCriteria authenticatorSelection = options.getAuthenticatorSelection();
      String optionsRk =
          authenticatorSelection != null ? authenticatorSelection.getResidentKey() : null;
      Boolean authenticatorRk = (Boolean) ctap.getCachedInfo().getOptions().get("rk");
      boolean rk =
          (ResidentKeyRequirement.REQUIRED.equals(optionsRk)
              || (ResidentKeyRequirement.PREFERRED.equals(optionsRk)
                  && Boolean.TRUE.equals(authenticatorRk)));

      return new RegistrationProcessor(
          (attestationObject, pinToken) ->
              serializationType ->
                  Collections.singletonMap(name, Collections.singletonMap("rk", rk)));
    }
    return null;
  }
}

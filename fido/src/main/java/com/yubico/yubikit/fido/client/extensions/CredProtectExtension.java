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
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import java.util.Collections;
import javax.annotation.Nullable;

/**
 * Implements the Credential Protection CTAP2 extension.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-credProtect-extension">Credential
 *     Protection (credProtect)</a>
 */
public class CredProtectExtension extends Extension {

  private static final String POLICY = "credentialProtectionPolicy";
  private static final String OPTIONAL = "userVerificationOptional";
  private static final String OPTIONAL_WITH_LIST = "userVerificationOptionalWithCredentialIDList";
  private static final String REQUIRED = "userVerificationRequired";
  private static final String ENFORCE = "enforceCredentialProtectionPolicy";

  public CredProtectExtension() {
    super("credProtect");
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

    String credentialProtectionPolicy = (String) extensions.get(POLICY);
    if (credentialProtectionPolicy == null) {
      return null;
    }

    Integer credProtect = credProtectValue(credentialProtectionPolicy);
    Boolean enforce = (Boolean) extensions.get(ENFORCE);
    if (Boolean.TRUE.equals(enforce)
        && !isSupported(ctap)
        && credProtect != null
        && credProtect > 0x01) {
      throw new IllegalArgumentException("No Credential Protection support");
    }
    return credProtect != null
        ? new RegistrationProcessor(pinToken -> Collections.singletonMap(name, credProtect))
        : null;
  }

  @Nullable
  private Integer credProtectValue(String optionsValue) {
    switch (optionsValue) {
      case OPTIONAL:
        return 0x01;
      case OPTIONAL_WITH_LIST:
        return 0x02;
      case REQUIRED:
        return 0x03;
      default:
        return null;
    }
  }
}

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

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import java.util.Collections;
import org.jspecify.annotations.Nullable;

/**
 * Implements the Credential Protection CTAP2 extension.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-credProtect-extension">Credential
 *     Protection (credProtect)</a>
 */
public class CredProtectExtension extends Extension {

  static final String POLICY = "credentialProtectionPolicy";
  static final String OPTIONAL = "userVerificationOptional";
  static final String OPTIONAL_WITH_LIST = "userVerificationOptionalWithCredentialIDList";
  static final String REQUIRED = "userVerificationRequired";
  static final String ENFORCE = "enforceCredentialProtectionPolicy";

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

    Object policyValue = extensions.get(POLICY);
    if (policyValue == null) {
      return null;
    }
    Integer credProtect =
        policyValue instanceof String ? credProtectValue((String) policyValue) : null;
    if (credProtect == null) {
      throw new IllegalArgumentException(
          "credentialProtectionPolicy must be a recognized policy value");
    }

    Object enforceValue = extensions.get(ENFORCE);
    if (enforceValue != null && !(enforceValue instanceof Boolean)) {
      throw new IllegalArgumentException("enforceCredentialProtectionPolicy must be a boolean");
    }
    boolean enforce = Boolean.TRUE.equals(enforceValue);
    if (enforce && !isSupported(ctap) && credProtect > 0x01) {
      throw new ExtensionConfigurationException("No Credential Protection support");
    }
    return new RegistrationProcessor(pinToken -> Collections.singletonMap(name, credProtect));
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

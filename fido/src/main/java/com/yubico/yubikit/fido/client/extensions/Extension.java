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

import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResultProvider;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import java.util.Collections;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * Base class for FIDO2 extensions.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">Webauthn Extensions</a>
 */
public abstract class Extension {
  protected final String name;

  protected Extension(String name) {
    this.name = name;
  }

  protected boolean isSupported(Ctap2Session ctap) {
    return ctap.getCachedInfo().getExtensions().contains(name);
  }

  @Nullable
  public RegistrationProcessor makeCredential(
      Ctap2Session ctap,
      PublicKeyCredentialCreationOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {
    return null;
  }

  @Nullable
  public AuthenticationProcessor getAssertion(
      Ctap2Session ctap,
      PublicKeyCredentialRequestOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {
    return null;
  }

  public interface RegistrationInput {
    @Nullable
    Map<String, Object> prepareInput(@Nullable byte[] pinToken);
  }

  public interface RegistrationOutput {
    @Nullable
    ClientExtensionResultProvider prepareOutput(
        AttestationObject attestationObject, @Nullable byte[] pinToken);
  }

  public interface AuthenticationInput {
    @Nullable
    Map<String, Object> prepareInput(
        @Nullable PublicKeyCredentialDescriptor selected, @Nullable byte[] pinToken);
  }

  public interface AuthenticationOutput {
    @Nullable
    ClientExtensionResultProvider prepareOutput(
        Ctap2Session.AssertionData assertionData, @Nullable byte[] pinToken);
  }

  public static class RegistrationProcessor {
    @Nullable private final RegistrationInput input;
    @Nullable private final RegistrationOutput output;
    private final int permissions;

    public RegistrationProcessor(
        @Nullable RegistrationInput input, @Nullable RegistrationOutput output, int permissions) {
      this.input = input;
      this.output = output;
      this.permissions = permissions;
    }

    public RegistrationProcessor(
        @Nullable RegistrationInput input, @Nullable RegistrationOutput output) {
      this(input, output, ClientPin.PIN_PERMISSION_NONE);
    }

    public RegistrationProcessor(@Nullable RegistrationInput input, int permissions) {
      this(input, null, permissions);
    }

    public RegistrationProcessor(@Nullable RegistrationInput input) {
      this(input, null);
    }

    public RegistrationProcessor(@Nullable RegistrationOutput output, int permissions) {
      this(null, output, permissions);
    }

    public RegistrationProcessor(@Nullable RegistrationOutput output) {
      this(null, output);
    }

    public Map<String, Object> getInput(@Nullable byte[] pinToken) {
      Map<String, Object> registrationInput = input != null ? input.prepareInput(pinToken) : null;
      return registrationInput != null ? registrationInput : Collections.emptyMap();
    }

    public ClientExtensionResultProvider getOutput(
        AttestationObject attestationObject, @Nullable byte[] pinToken) {
      ClientExtensionResultProvider resultProvider =
          output != null ? output.prepareOutput(attestationObject, pinToken) : null;
      return resultProvider != null ? resultProvider : serializationType -> Collections.emptyMap();
    }

    public int getPermissions() {
      return permissions;
    }
  }

  public static class AuthenticationProcessor {
    @Nullable private final AuthenticationInput input;
    @Nullable private final AuthenticationOutput output;
    private final int permissions;

    public AuthenticationProcessor(
        @Nullable AuthenticationInput input,
        @Nullable AuthenticationOutput output,
        int permissions) {
      this.input = input;
      this.output = output;
      this.permissions = permissions;
    }

    public AuthenticationProcessor(
        @Nullable AuthenticationInput input, @Nullable AuthenticationOutput output) {
      this(input, output, ClientPin.PIN_PERMISSION_NONE);
    }

    public AuthenticationProcessor(@Nullable AuthenticationInput input, int permissions) {
      this(input, null, permissions);
    }

    public AuthenticationProcessor(@Nullable AuthenticationInput input) {
      this(input, null);
    }

    public AuthenticationProcessor(@Nullable AuthenticationOutput output, int permissions) {
      this(null, output, permissions);
    }

    public AuthenticationProcessor(@Nullable AuthenticationOutput output) {
      this(null, output);
    }

    public Map<String, Object> getInput(
        @Nullable PublicKeyCredentialDescriptor selected, @Nullable byte[] pinToken) {
      Map<String, Object> authenticatorInput =
          input != null ? input.prepareInput(selected, pinToken) : null;
      return authenticatorInput != null ? authenticatorInput : Collections.emptyMap();
    }

    public ClientExtensionResultProvider getOutput(
        Ctap2Session.AssertionData assertionData, @Nullable byte[] pinToken) {
      ClientExtensionResultProvider resultProvider =
          output != null ? output.prepareOutput(assertionData, pinToken) : null;
      return resultProvider != null ? resultProvider : serializationType -> Collections.emptyMap();
    }

    public int getPermissions() {
      return permissions;
    }
  }
}

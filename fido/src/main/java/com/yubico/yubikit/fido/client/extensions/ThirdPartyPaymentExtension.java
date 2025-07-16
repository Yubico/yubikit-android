/*
 * Copyright (C) 2025 Yubico.
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
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import java.util.Collections;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * Implements the Third-party payment authentication (thirdPartyPayment) CTAP2 extension.
 *
 * <p>This extension allows a Relying Party to indicate that a credential can be used for Payment
 * authentication initiated by a party (website or native application) that is not the Relying
 * Party.
 *
 * <p>Note that most of the processing for the WebAuthn extension needs to be done by the client.
 * Therefore this extension is not included in the default extensions list, and should not be used
 * without a client that supports the WebAuthn payment extension.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-thirdPartyPayment-extension">Third-Party
 *     Payment authentication (thirdPartyPayment)</a>
 * @see <a href="https://www.w3.org/TR/secure-payment-confirmation">Secure Payment Confirmation</a>
 */
public class ThirdPartyPaymentExtension extends Extension {

  private static final String THIRD_PARTY_PAYMENT = "thirdPartyPayment";
  private static final String PAYMENT = "payment";
  private static final String IS_PAYMENT = "isPayment";

  public ThirdPartyPaymentExtension() {
    super(THIRD_PARTY_PAYMENT);
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

    Boolean isPayment = getIsPayment(options.getExtensions());
    if (isPayment == null) {
      return null;
    }

    return new RegistrationProcessor(
        (pinToken) ->
            Collections.singletonMap(THIRD_PARTY_PAYMENT, Boolean.TRUE.equals(isPayment)));
  }

  @Nullable
  @Override
  public AuthenticationProcessor getAssertion(
      Ctap2Session ctap,
      PublicKeyCredentialRequestOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {

    if (!isSupported(ctap)) {
      return null;
    }

    Boolean isPayment = getIsPayment(options.getExtensions());
    if (isPayment == null) {
      return null;
    }

    final AuthenticationInput prepareInput =
        (selected, pinToken) ->
            Collections.singletonMap(THIRD_PARTY_PAYMENT, Boolean.TRUE.equals(isPayment));

    return new AuthenticationProcessor(prepareInput);
  }

  @SuppressWarnings("unchecked")
  @Nullable
  private Boolean getIsPayment(@Nullable Extensions extensions) {
    if (extensions == null) {
      return null;
    }

    Map<String, ?> payment = (Map<String, ?>) extensions.get(PAYMENT);
    if (payment == null) {
      return null;
    }

    return (Boolean) payment.get(IS_PAYMENT);
  }
}

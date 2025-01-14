/*
 * Copyright (C) 2020-2023 Yubico.
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

package com.yubico.yubikit.fido.client;

import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAssertionResponse;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The request generated multiple assertions, and a choice must be made by the user. Once selected,
 * call {@link #select(int)} to get an assertion.
 */
public class MultipleAssertionsAvailable extends Throwable {
  private final byte[] clientDataJson;
  private final List<Pair<Ctap2Session.AssertionData, ClientExtensionResults>> assertions;

  MultipleAssertionsAvailable(
      byte[] clientDataJson,
      List<Pair<Ctap2Session.AssertionData, ClientExtensionResults>> assertions) {
    super("Request returned multiple assertions");

    this.clientDataJson = clientDataJson;
    this.assertions = assertions;
  }

  /**
   * Get the number of assertions returned by the Authenticators.
   *
   * @return the number of assertions available
   */
  public int getAssertionCount() {
    return assertions.size();
  }

  /**
   * The list of users for which credentials are stored by the Authenticator. The indexes of the
   * user objects correspond to the value which should be passed to select() to select a response.
   *
   * <p>NOTE: If PIV/UV wasn't provided to the call to {@link BasicWebAuthnClient#getAssertion} then
   * user information may not be available, in which case this method will throw an exception.
   *
   * @return a list of available users.
   * @throws UserInformationNotAvailableError in case PIN/UV wasn't provided
   */
  public List<PublicKeyCredentialUserEntity> getUsers() throws UserInformationNotAvailableError {
    List<PublicKeyCredentialUserEntity> users = new ArrayList<>();
    for (Pair<Ctap2Session.AssertionData, ClientExtensionResults> assertion : assertions) {
      Map<String, ?> user = assertion.first.getUser();
      if (user == null) {
        throw new UserInformationNotAvailableError();
      }

      users.add(PublicKeyCredentialUserEntity.fromMap(user, SerializationType.CBOR));
    }
    return users;
  }

  /**
   * Selects which assertion to use by index. These indices correspond to those of the List returned
   * by {@link #getUsers()}. This method can only be called once to get a single response.
   *
   * @param index The index of the assertion to return.
   * @return A WebAuthn public key credential.
   */
  public PublicKeyCredential select(int index) {
    if (assertions.isEmpty()) {
      throw new IllegalStateException("Assertion has already been selected");
    }
    Pair<Ctap2Session.AssertionData, ClientExtensionResults> assertionPair = assertions.get(index);
    assertions.clear();

    final Ctap2Session.AssertionData assertion = assertionPair.first;
    final ClientExtensionResults clientExtensionResults = assertionPair.second;

    final Map<String, ?> user = Objects.requireNonNull(assertion.getUser());
    final Map<String, ?> credential = Objects.requireNonNull(assertion.getCredential());
    final byte[] credentialId =
        Objects.requireNonNull((byte[]) credential.get(PublicKeyCredentialDescriptor.ID));
    return new PublicKeyCredential(
        credentialId,
        new AuthenticatorAssertionResponse(
            clientDataJson,
            assertion.getAuthenticatorData(),
            assertion.getSignature(),
            Objects.requireNonNull((byte[]) user.get(PublicKeyCredentialUserEntity.ID))),
        clientExtensionResults);
  }
}

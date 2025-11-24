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

package com.yubico.yubikit.fido.client;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider;
import com.yubico.yubikit.fido.ctap.CtapSession;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import java.io.Closeable;
import java.io.IOException;
import org.jspecify.annotations.Nullable;

public interface CtapClient extends Closeable {

  /**
   * Returns the underlying CTAP session.
   *
   * @return the {@link CtapSession} associated with this client
   */
  CtapSession getSession();

  /**
   * Creates a new credential using the CTAP protocol.
   *
   * @param clientData provider for client data
   * @param options options for credential creation
   * @param effectiveDomain effective domain for RP ID validation
   * @param pin PIN for authorization (if required)
   * @param enterpriseAttestation enterprise attestation parameter (if supported)
   * @param state optional command state for operation control
   * @return a {@link PublicKeyCredential} representing the created credential
   * @throws IOException if a transport error occurs
   * @throws CommandException if a protocol error occurs
   * @throws ClientError for higher-level client errors
   */
  PublicKeyCredential makeCredential(
      ClientDataProvider clientData,
      PublicKeyCredentialCreationOptions options,
      String effectiveDomain,
      char @Nullable [] pin,
      @Nullable Integer enterpriseAttestation,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError;

  /**
   * Performs an assertion (authentication) using the CTAP protocol.
   *
   * @param clientData provider for client data
   * @param options options for the assertion request
   * @param effectiveDomain effective domain for RP ID validation
   * @param pin PIN for authorization (if required)
   * @param state optional command state for operation control
   * @return a {@link PublicKeyCredential} containing the assertion result
   * @throws MultipleAssertionsAvailable if multiple assertions are available (CTAP2 only)
   * @throws IOException if a transport error occurs
   * @throws CommandException if a protocol error occurs
   * @throws ClientError for higher-level client errors
   */
  PublicKeyCredential getAssertion(
      ClientDataProvider clientData,
      PublicKeyCredentialRequestOptions options,
      String effectiveDomain,
      char @Nullable [] pin,
      @Nullable CommandState state)
      throws MultipleAssertionsAvailable, IOException, CommandException, ClientError;
}

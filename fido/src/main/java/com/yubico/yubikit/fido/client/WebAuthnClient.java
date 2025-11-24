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
import com.yubico.yubikit.fido.client.extensions.Extension;
import com.yubico.yubikit.fido.ctap.Ctap1Session;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.CtapSession;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * A unified WebAuthn client that works with both CTAP1 and CTAP2 protocols.
 *
 * <p>This client automatically detects the CTAP protocol version from the session and delegates to
 * the appropriate implementation (Ctap1Client or BasicWebAuthnClient). This provides a single,
 * unified API for WebAuthn operations regardless of the underlying protocol version.
 *
 * <p>Key features:
 *
 * <ul>
 *   <li>Automatic protocol detection and delegation
 *   <li>Unified API for both CTAP1 (U2F) and CTAP2 (WebAuthn) protocols
 *   <li>Support for makeCredential and getAssertion operations
 *   <li>Extensible design for future protocol versions
 * </ul>
 *
 * <p>Usage example:
 *
 * <pre>{@code
 * CtapSession session = ...; // Either Ctap1Session or Ctap2Session
 * WebAuthnClient client = new WebAuthnClient(session);
 * PublicKeyCredential credential = client.makeCredential(...);
 * }</pre>
 *
 * @see Ctap1Client
 * @see BasicWebAuthnClient
 * @see CtapSession
 */
public class WebAuthnClient implements Closeable {

  private final CtapClient ctapClient;

  /**
   * Create a new WebAuthn client from a CTAP session with specific extensions.
   *
   * <p>Note: Extensions are only supported for CTAP2 sessions. For CTAP1 sessions, the extensions
   * parameter is ignored.
   *
   * @param session The CTAP session (either Ctap1Session or Ctap2Session)
   * @param extensions List of extensions (only applicable for CTAP2), passing null will use default
   *     extension set
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication error in the protocol layer (CTAP2 only)
   * @throws IllegalArgumentException If the session type is not supported
   */
  public WebAuthnClient(CtapSession session, @Nullable List<Extension> extensions)
      throws IOException, CommandException {

    if (session instanceof Ctap2Session) {
      this.ctapClient = new BasicWebAuthnClient((Ctap2Session) session, extensions);
    } else if (session instanceof Ctap1Session) {
      this.ctapClient = new Ctap1Client((Ctap1Session) session);
    } else {
      throw new IllegalArgumentException(
          "Unsupported session type: " + session.getClass().getName());
    }
  }

  /**
   * Create a new WebAuthn credential.
   *
   * <p>For CTAP1: PIN and enterprise attestation parameters are ignored. For CTAP2: All parameters
   * are supported.
   *
   * @param clientData The {@link ClientDataProvider} instance supplying client data for the request
   * @param options The options for creating the credential
   * @param effectiveDomain The effective domain for the request, used to validate the RP ID
   * @param pin If needed, the PIN to authorize the credential creation (CTAP2 only)
   * @param enterpriseAttestation Enterprise attestation parameter (CTAP2 only)
   * @param state If needed, the state to provide control over the ongoing operation
   * @return A WebAuthn public key credential
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication error in the protocol layer
   * @throws ClientError A higher level error
   */
  public PublicKeyCredential makeCredential(
      ClientDataProvider clientData,
      PublicKeyCredentialCreationOptions options,
      String effectiveDomain,
      char @Nullable [] pin,
      @Nullable Integer enterpriseAttestation,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {
    return ctapClient.makeCredential(
        clientData, options, effectiveDomain, pin, enterpriseAttestation, state);
  }

  /**
   * Authenticate an existing WebAuthn credential.
   *
   * <p>For CTAP1: PIN parameter is ignored, allowCredentials list is required. For CTAP2: PIN is
   * supported, allowCredentials list is optional for discoverable credentials.
   *
   * <p>If multiple assertions are available (CTAP2 only), a {@link MultipleAssertionsAvailable}
   * exception will be thrown which can be handled to select a specific assertion.
   *
   * @param clientData The {@link ClientDataProvider} instance supplying client data for the request
   * @param options The options for the authentication request
   * @param effectiveDomain The effective domain for the request, used to validate the RP ID
   * @param pin If needed, the PIN to authorize the assertion (CTAP2 only)
   * @param state If needed, the state to provide control over the ongoing operation
   * @return A WebAuthn public key credential with assertion
   * @throws MultipleAssertionsAvailable Multiple discoverable credentials found (CTAP2 only)
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication error in the protocol layer
   * @throws ClientError A higher level error
   */
  public PublicKeyCredential getAssertion(
      ClientDataProvider clientData,
      PublicKeyCredentialRequestOptions options,
      String effectiveDomain,
      char @Nullable [] pin,
      @Nullable CommandState state)
      throws MultipleAssertionsAvailable, IOException, CommandException, ClientError {
    return ctapClient.getAssertion(clientData, options, effectiveDomain, pin, state);
  }

  /**
   * Returns the underlying CTAP client implementation.
   *
   * <p>This allows access to protocol-specific operations or advanced features not exposed by the
   * unified {@link WebAuthnClient} API.
   *
   * @return the {@link CtapClient} instance used by this client
   */
  public CtapClient getClient() {
    return ctapClient;
  }

  @Override
  public void close() throws IOException {
    ctapClient.close();
  }
}

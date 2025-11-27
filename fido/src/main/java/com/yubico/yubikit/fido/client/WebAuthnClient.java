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

import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider;
import com.yubico.yubikit.fido.client.extensions.Extension;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * Protocol-agnostic interface for WebAuthn operations.
 *
 * <p>Implementations provide support for specific CTAP protocol versions (e.g., CTAP1/U2F,
 * CTAP2/WebAuthn). Use {@link #create(YubiKeyDevice, List)} or {@link #create(YubiKeyConnection,
 * List, ScpKeyParams)} to obtain the correct implementation for a given session.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/">WebAuthn</a>
 * @see Ctap1Client
 * @see Ctap2Client
 */
public interface WebAuthnClient extends Closeable {

  /**
   * Create a new WebAuthn client from a YubiKey device with specific extensions.
   *
   * <p>Note: Extensions are only supported for CTAP2 sessions. For CTAP1 sessions, the extensions
   * parameter is ignored.
   *
   * @param device The YubiKey device to use for the session
   * @param extensions List of extensions (only applicable for CTAP2), passing null will use default
   *     extension set
   * @return A WebAuthnClient instance for the given device
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication error in the protocol layer (CTAP2 only)
   */
  static WebAuthnClient create(YubiKeyDevice device, @Nullable List<Extension> extensions)
      throws IOException, CommandException {
    return Utils.createWebAuthnClient(device, extensions);
  }

  /**
   * Create a new WebAuthn client from a YubiKey connection with specific extensions and optional
   * SCP key parameters.
   *
   * <p>Note: Extensions are only supported for CTAP2 sessions. For CTAP1 sessions, the extensions
   * parameter is ignored.
   *
   * @param connection The YubiKey connection to use for the session
   * @param extensions List of extensions (only applicable for CTAP2), passing null will use default
   *     extension set
   * @param scpKeyParams Optional SCP key parameters for secure channel (may be null)
   * @return A WebAuthnClient instance for the given connection
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication error in the protocol layer (CTAP2 only)
   */
  static WebAuthnClient create(
      YubiKeyConnection connection,
      @Nullable List<Extension> extensions,
      @Nullable ScpKeyParams scpKeyParams)
      throws IOException, CommandException {
    return Utils.createWebAuthnClient(connection, extensions, scpKeyParams);
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
  PublicKeyCredential makeCredential(
      ClientDataProvider clientData,
      PublicKeyCredentialCreationOptions options,
      String effectiveDomain,
      char @Nullable [] pin,
      @Nullable Integer enterpriseAttestation,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError;

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
  PublicKeyCredential getAssertion(
      ClientDataProvider clientData,
      PublicKeyCredentialRequestOptions options,
      String effectiveDomain,
      char @Nullable [] pin,
      @Nullable CommandState state)
      throws MultipleAssertionsAvailable, IOException, CommandException, ClientError;
}

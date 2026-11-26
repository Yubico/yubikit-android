/*
 * Copyright (C) 2025-2026 Yubico.
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
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.fido.client.extensions.Extension;
import com.yubico.yubikit.fido.ctap.Ctap1Session;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Utils {

  private static final Logger logger = LoggerFactory.getLogger(Utils.class);

  static final int ALG_ES256 = -7;
  static final int ALG_RS256 = -257;

  private Utils() {}

  /**
   * Rejects a user id that is not 1 to 64 bytes long, as WebAuthn requires.
   *
   * @see <a href="https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-createCredential">Create
   *     a New Credential</a>
   */
  /**
   * Creates the attestation response, reporting a credential that cannot be read, such as a
   * malformed COSE public key from the authenticator, as a bad response instead of an unchecked
   * exception.
   */
  static AuthenticatorAttestationResponse attestationResponse(
      byte[] clientDataJson, List<String> transports, AttestationObject attestationObject)
      throws BadResponseException {
    try {
      return new AuthenticatorAttestationResponse(clientDataJson, transports, attestationObject);
    } catch (ClassCastException | NullPointerException | IllegalArgumentException e) {
      throw new BadResponseException("Malformed credential in makeCredential response", e);
    }
  }

  static void checkUserId(PublicKeyCredentialCreationOptions options) throws ClientError {
    int length = options.getUser().getId().length;
    if (length < 1 || length > 64) {
      throw new ClientError(ClientError.Code.BAD_REQUEST, "user.id must be 1 to 64 bytes long");
    }
  }

  /**
   * Returns the credential parameters to request, defaulting to ES256 and RS256 when the RP passed
   * an empty list, as WebAuthn requires.
   */
  static List<PublicKeyCredentialParameters> getPubKeyCredParams(
      PublicKeyCredentialCreationOptions options) {
    List<PublicKeyCredentialParameters> params = options.getPubKeyCredParams();
    if (!params.isEmpty()) {
      return params;
    }
    return Arrays.asList(
        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, ALG_ES256),
        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, ALG_RS256));
  }

  /**
   * Return SHA-256 hash of the provided input
   *
   * @param message The hash input
   * @return SHA-256 of the input
   */
  public static byte[] hash(byte[] message) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(message);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  static WebAuthnClient createWebAuthnClient(
      YubiKeyDevice device, @Nullable List<Extension> extensions)
      throws IOException, CommandException {
    try {
      return createWebAuthnClient(device.openConnection(FidoConnection.class), extensions, null);
    } catch (Exception e) {
      return createWebAuthnClient(
          device.openConnection(SmartCardConnection.class), extensions, null);
    }
  }

  static WebAuthnClient createWebAuthnClient(
      YubiKeyConnection connection,
      @Nullable List<Extension> extensions,
      @Nullable ScpKeyParams scpKeyParams)
      throws IOException, CommandException {
    if (connection instanceof FidoConnection && scpKeyParams != null) {
      throw new IllegalArgumentException("ScpKeyParams provided for FidoConnection");
    }
    try {
      return new Ctap2Client(createCtap2Session(connection, scpKeyParams), extensions);
    } catch (Exception e) {
      return new Ctap1Client(createCtap1Session(connection, scpKeyParams));
    }
  }

  static Ctap2Session createCtap2Session(
      YubiKeyConnection connection, @Nullable ScpKeyParams scpKeyParams)
      throws IOException, CommandException, IllegalArgumentException {
    if (connection instanceof FidoConnection) {
      logger.debug("Attempting to create Ctap2Session from FidoConnection");
      return new Ctap2Session((FidoConnection) connection);
    } else if (connection instanceof SmartCardConnection) {
      logger.debug("Attempting to create Ctap2Session from SmartCardConnection with SCP params");
      return new Ctap2Session((SmartCardConnection) connection, scpKeyParams);
    } else {
      throw new IllegalArgumentException(
          "Unsupported connection type: "
              + connection.getClass().getName()
              + ". Expected FidoConnection or SmartCardConnection.");
    }
  }

  static Ctap1Session createCtap1Session(
      YubiKeyConnection connection, @Nullable ScpKeyParams scpKeyParams)
      throws IOException, CommandException, IllegalArgumentException {
    if (connection instanceof FidoConnection) {
      logger.debug("Attempting to create Ctap1Session from FidoConnection");
      return new Ctap1Session((FidoConnection) connection);
    } else if (connection instanceof SmartCardConnection) {
      logger.debug("Attempting to create Ctap1Session from SmartCardConnection");
      return new Ctap1Session((SmartCardConnection) connection, scpKeyParams);
    } else {
      throw new IllegalArgumentException(
          "Unsupported connection type: "
              + connection.getClass().getName()
              + ". Expected FidoConnection or SmartCardConnection.");
    }
  }
}

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

import static com.yubico.yubikit.fido.client.Utils.hash;

import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider;
import com.yubico.yubikit.fido.ctap.Ctap1Session;
import com.yubico.yubikit.fido.ctap.CtapSession;
import com.yubico.yubikit.fido.webauthn.AttestationConveyancePreference;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAssertionResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import com.yubico.yubikit.fido.webauthn.UserVerificationRequirement;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import org.jspecify.annotations.Nullable;

public class Ctap1Client implements CtapClient {
  private final Ctap1Session ctap1;

  public Ctap1Client(Ctap1Session session) {
    this.ctap1 = session;
  }

  @Override
  public CtapSession getSession() {
    return ctap1;
  }

  /**
   * Creates a new credential using the CTAP protocol.
   *
   * @param clientData provider for client data
   * @param options options for credential creation
   * @param effectiveDomain effective domain for RP ID validation
   * @param pin ignored
   * @param enterpriseAttestation ignored
   * @param state optional command state for operation control
   * @return a {@link PublicKeyCredential} representing the created credential
   * @throws IOException if a transport error occurs
   * @throws ClientError for higher-level client errors
   */
  @Override
  public PublicKeyCredential makeCredential(
      ClientDataProvider clientData,
      PublicKeyCredentialCreationOptions options,
      String effectiveDomain,
      char @Nullable [] pin,
      @Nullable Integer enterpriseAttestation,
      @Nullable CommandState state)
      throws IOException, ClientError {
    try {
      String rpId = options.getRp().getId();
      if (rpId == null) {
        rpId = effectiveDomain;
      } else if (!effectiveDomain.equals(rpId) && !effectiveDomain.endsWith("." + rpId)) {
        throw new ClientError(
            ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
      }

      // Check for unsupported features
      if (options.getAuthenticatorSelection() != null) {
        if (ResidentKeyRequirement.REQUIRED.equals(
            options.getAuthenticatorSelection().getResidentKey())) {
          throw new ClientError(
              ClientError.Code.CONFIGURATION_UNSUPPORTED, "Resident keys not supported by CTAP1");
        }
        if (UserVerificationRequirement.REQUIRED.equals(
            options.getAuthenticatorSelection().getUserVerification())) {
          throw new ClientError(
              ClientError.Code.CONFIGURATION_UNSUPPORTED,
              "User verification not supported by CTAP1");
        }
      }

      // Check for ES256 support
      boolean hasEs256 = false;
      for (PublicKeyCredentialParameters param : options.getPubKeyCredParams()) {
        if (param.getAlg() == -7) { // ES256
          hasEs256 = true;
          break;
        }
      }
      if (!hasEs256) {
        throw new ClientError(
            ClientError.Code.CONFIGURATION_UNSUPPORTED, "CTAP1 only supports ES256 algorithm");
      }

      // Reject Enterprise Attestation
      if (AttestationConveyancePreference.ENTERPRISE.equalsIgnoreCase(options.getAttestation())) {
        throw new ClientError(
            ClientError.Code.CONFIGURATION_UNSUPPORTED,
            "Enterprise attestation not supported by CTAP1");
      }

      // Exclude list handling
      List<PublicKeyCredentialDescriptor> excludeList = options.getExcludeCredentials();
      if (!excludeList.isEmpty()) {
        byte[] appParam = hash(rpId.getBytes(StandardCharsets.UTF_8));
        byte[] dummy = new byte[32];
        for (PublicKeyCredentialDescriptor cred : excludeList) {
          try {
            ctap1.authenticate(dummy, appParam, cred.getId(), true, state);
            // Should not succeed
            throw new ClientError(
                ClientError.Code.OTHER_ERROR,
                "Authentication should not succeed for excluded credential");
          } catch (ApduException e) {
            if (e.getSw() == SW.CONDITIONS_NOT_SATISFIED) {
              try {
                callPolling(() -> ctap1.register(dummy, dummy, state));
              } catch (Exception ex) {
                throw new ClientError(ClientError.Code.OTHER_ERROR, e);
              }
              throw new ClientError(ClientError.Code.DEVICE_INELIGIBLE, e);
            }
            throw convertApduException(e);
          } catch (CtapException e) {
            throw ClientError.wrapCtapException(e);
          } catch (Exception e) {
            throw new IOException(e);
          }
        }
      }

      byte[] appParam = hash(rpId.getBytes(StandardCharsets.UTF_8));
      byte[] clientDataHash = clientData.getHash();

      Ctap1Session.RegistrationData regData;
      try {
        regData = callPolling(() -> ctap1.register(clientDataHash, appParam, state));
      } catch (CtapException e) {
        throw ClientError.wrapCtapException(e);
      } catch (ApduException | ClientError e) {
        throw e;
      } catch (Exception e) {
        throw new IOException(e);
      }

      AttestationObject attestationObject = regData.getAttestation(appParam);
      AuthenticatorAttestationResponse response =
          new AuthenticatorAttestationResponse(
              clientData.getClientDataJson(), Collections.emptyList(), attestationObject);
      return new PublicKeyCredential(
          regData.getKeyHandle(), response, new ClientExtensionResults());
    } catch (ApduException e) {
      throw convertApduException(e);
    }
  }

  /**
   * Performs an assertion (authentication) using the CTAP protocol.
   *
   * @param clientData provider for client data
   * @param options options for the assertion request
   * @param effectiveDomain effective domain for RP ID validation
   * @param pin ignored
   * @param state optional command state for operation control
   * @return a {@link PublicKeyCredential} containing the assertion result
   * @throws IOException if a transport error occurs
   * @throws ClientError for higher-level client errors
   */
  @Override
  public PublicKeyCredential getAssertion(
      ClientDataProvider clientData,
      PublicKeyCredentialRequestOptions options,
      String effectiveDomain,
      char @Nullable [] pin,
      @Nullable CommandState state)
      throws IOException, ClientError {
    try {
      String rpId = options.getRpId();
      if (rpId == null) {
        rpId = effectiveDomain;
      } else if (!effectiveDomain.equals(rpId) && !effectiveDomain.endsWith("." + rpId)) {
        throw new ClientError(
            ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
      }
      List<PublicKeyCredentialDescriptor> allowCredentials = options.getAllowCredentials();
      if (allowCredentials.isEmpty()) {
        throw new ClientError(
            ClientError.Code.CONFIGURATION_UNSUPPORTED, "CTAP1 requires allowCredentials list");
      }

      byte[] appParam = hash(rpId.getBytes(StandardCharsets.UTF_8));
      byte[] clientDataHash = clientData.getHash();
      ApduException lastException = null;
      for (PublicKeyCredentialDescriptor descriptor : allowCredentials) {
        try {
          Ctap1Session.SignatureData sigData =
              callPolling(
                  () ->
                      ctap1.authenticate(
                          clientDataHash, appParam, descriptor.getId(), false, state));
          ByteBuffer authDataBuffer =
              ByteBuffer.allocate(appParam.length + 1 + 4)
                  .put(appParam)
                  .put(sigData.getUserPresence())
                  .putInt(sigData.getCounter());
          AuthenticatorAssertionResponse assertionResponse =
              new AuthenticatorAssertionResponse(
                  clientData.getClientDataJson(),
                  authDataBuffer.array(),
                  sigData.getSignature(),
                  null);
          return new PublicKeyCredential(
              descriptor.getId(), assertionResponse, new ClientExtensionResults());
        } catch (ApduException e) {
          if (e.getSw() == SW.CONDITIONS_NOT_SATISFIED) {
            lastException = e;
            continue;
          }
          throw e;
        } catch (Exception e) {
          if (e instanceof ClientError) throw (ClientError) e;
          throw new IOException(e);
        }
      }
      if (lastException != null) {
        throw new ClientError(ClientError.Code.DEVICE_INELIGIBLE, lastException);
      }
      throw new ClientError(ClientError.Code.DEVICE_INELIGIBLE, "No matching credentials found");
    } catch (ApduException e) {
      throw convertApduException(e);
    }
  }

  @Override
  public void close() throws IOException {
    ctap1.close();
  }

  /** Polling utility for CTAP1 operations. Retries the callable on CONDITIONS_NOT_SATISFIED. */
  private <T> T callPolling(Callable<T> func) throws Exception {
    final int POLL_INTERVAL = 250;
    Exception lastError = null;
    while (lastError == null) {
      try {
        return func.call();
      } catch (ApduException e) {
        if (e.getSw() == SW.CONDITIONS_NOT_SATISFIED) {
          synchronized (this) {
            try {
              wait(POLL_INTERVAL);
            } catch (InterruptedException interruptedException) {
              Thread.currentThread().interrupt();
              lastError = interruptedException;
            }
          }
        } else {
          lastError = e;
        }
      }
    }
    throw new ClientError(ClientError.Code.OTHER_ERROR, lastError);
  }

  private static ClientError convertApduException(ApduException e) {
    short sw = e.getSw();
    if (sw == SW.CONDITIONS_NOT_SATISFIED) {
      return new ClientError(ClientError.Code.TIMEOUT, e);
    } else if (sw == SW.INCORRECT_PARAMETERS) {
      return new ClientError(ClientError.Code.BAD_REQUEST, e);
    } else {
      return new ClientError(ClientError.Code.OTHER_ERROR, e);
    }
  }
}

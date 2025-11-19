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
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider;
import com.yubico.yubikit.fido.ctap.Ctap1Session;
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
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Ctap1Client implements Closeable {
  private final Ctap1Session ctap1;
  private final Logger logger = LoggerFactory.getLogger(Ctap1Client.class);
  private final CommandState defaultState = new CommandState();

  public Ctap1Client(Ctap1Session session) {
    this.ctap1 = session;
  }

  @Override
  public void close() throws IOException {
    ctap1.close();
  }

  public PublicKeyCredential makeCredential(
      ClientDataProvider clientData,
      PublicKeyCredentialCreationOptions options,
      String effectiveDomain,
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
            callPolling(() -> ctap1.authenticate(dummy, appParam, cred.getId(), true), state);
            // If authenticate succeeds, credential is already registered
            throw new ClientError(
                ClientError.Code.DEVICE_INELIGIBLE,
                "Credential in exclude list already registered");
          } catch (ClientError e) {
            throw e;
          } catch (Exception e) {
            throw new IOException(e);
          }
        }
      }

      byte[] appParam = hash(rpId.getBytes(StandardCharsets.UTF_8));
      byte[] clientDataHash = clientData.getHash();

      Ctap1Session.RegistrationData regData;
      try {
        regData = callPolling(() -> ctap1.register(clientDataHash, appParam), state);
      } catch (Exception e) {
        if (e instanceof ClientError) throw (ClientError) e;
        if (e instanceof ApduException) throw (ApduException) e;
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

  public PublicKeyCredential getAssertion(
      ClientDataProvider clientData,
      PublicKeyCredentialRequestOptions options,
      String effectiveDomain,
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
                  () -> ctap1.authenticate(clientDataHash, appParam, descriptor.getId(), false),
                  state);
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

  /**
   * Polling utility for CTAP1 operations. Retries the callable on CONDITIONS_NOT_SATISFIED.
   * Cancellable through provided CommandState
   */
  private <T> T callPolling(Callable<T> func, @Nullable CommandState state) throws Exception {
    final int POLL_INTERVAL = 250;
    boolean keepaliveSent = false;
    state = state == null ? defaultState : state;
    do {
      try {
        return func.call();
      } catch (ApduException e) {
        if (e.getSw() == SW.CONDITIONS_NOT_SATISFIED) {
          if (!keepaliveSent) {
            state.onKeepAliveStatus(CommandState.STATUS_UPNEEDED);
            keepaliveSent = true;
          }
        } else {
          throw new ClientError(ClientError.Code.OTHER_ERROR, e);
        }
      }
    } while (!state.waitForCancel(POLL_INTERVAL));

    throw new ClientError(ClientError.Code.TIMEOUT, "Time out");
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

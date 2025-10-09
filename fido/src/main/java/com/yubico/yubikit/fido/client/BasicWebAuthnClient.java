/*
 * Copyright (C) 2020-2025 Yubico.
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

import static com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType.PUBLIC_KEY;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.client.extensions.CredBlobExtension;
import com.yubico.yubikit.fido.client.extensions.CredPropsExtension;
import com.yubico.yubikit.fido.client.extensions.CredProtectExtension;
import com.yubico.yubikit.fido.client.extensions.Extension;
import com.yubico.yubikit.fido.client.extensions.HmacSecretExtension;
import com.yubico.yubikit.fido.client.extensions.LargeBlobExtension;
import com.yubico.yubikit.fido.client.extensions.MinPinLengthExtension;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthDummyProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.fido.webauthn.AttestationConveyancePreference;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import com.yubico.yubikit.fido.webauthn.UserVerificationRequirement;
import java.io.Closeable;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

/**
 * A "basic" WebAuthn client implementation which wraps a YubiKeySession.
 *
 * <p>Provides the following functionality:
 *
 * <ul>
 *   <li>MakeCredential: Registers a new credential. If a PIN is needed, it is passed to this
 *       method.
 *   <li>GetAssertion: Authenticate an existing credential. If a PIN is needed, it is passed to this
 *       method.
 *   <li>PIN Management: Set or change the PIN code of an Authenticator, or see its state.
 *   <li>Credential Management: List or delete resident credentials of an Authenticator.
 * </ul>
 *
 * The timeout parameter in the request options is ignored. To cancel a request pass a {@link
 * CommandState} instance to the call and use its cancel method.
 */
@SuppressWarnings("unused")
public class BasicWebAuthnClient implements Closeable {
  private static final String OPTION_CLIENT_PIN = "clientPin";
  private static final String OPTION_USER_VERIFICATION = "uv";
  private static final String OPTION_BIO_ENROLLMENT = "bioEnroll";
  private static final String OPTION_RESIDENT_KEY = "rk";
  private static final String OPTION_EP = "ep";
  private static final String OPTION_ALWAYS_UV = "alwaysUv";
  private static final String OPTION_MC_UV_NOT_RQD = "makeCredUvNotRqd";

  private final UserAgentConfiguration userAgentConfiguration = new UserAgentConfiguration();

  private final Ctap2Session ctap;

  private final boolean pinSupported;
  private final boolean uvSupported;
  private final boolean bioEnrollSupported;
  private final boolean rkSupported;

  private final ClientPin clientPin;

  private boolean pinConfigured;
  private final boolean uvConfigured;
  private final boolean bioEnrollConfigured;

  private final boolean enterpriseAttestationSupported;

  private final List<Extension> extensions;

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(BasicWebAuthnClient.class);

  public static class UserAgentConfiguration {
    private List<String> epSupportedRpIds = new ArrayList<>();

    public void setEpSupportedRpIds(List<String> epSupportedRpIds) {
      this.epSupportedRpIds = epSupportedRpIds;
    }

    boolean supportsEpForRpId(@Nullable String rpId) {
      return epSupportedRpIds.contains(rpId);
    }
  }

  private static class AuthParams {
    @Nullable private final byte[] pinToken;
    private final boolean internalUv;

    AuthParams(@Nullable byte[] pinToken, boolean internalUv) {
      this.pinToken = pinToken;
      this.internalUv = internalUv;
    }
  }

  /**
   * Create a new Webauthn client.
   *
   * <p>This client will process all extensions.
   *
   * @param session CTAP session
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication in the protocol layer
   * @see <a href="https://www.w3.org/TR/webauthn-2/#webauthn-client">Webauthn client</a>
   * @see <a href="https://www.w3.org/TR/webauthn-2/#sctn-extensions">Webauthn extensions</a>
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-defined-extensions">CTAP
   *     extensions</a>
   */
  public BasicWebAuthnClient(Ctap2Session session) throws IOException, CommandException {
    this(session, defaultExtensions);
  }

  /**
   * Create a new Webauthn client.
   *
   * <p>This client will only process provided extensions.
   *
   * @param session CTAP2 session
   * @param extensions List of extensions
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication in the protocol layer
   * @see <a href="https://www.w3.org/TR/webauthn-2/#webauthn-client">Webauthn client</a>
   * @see <a href="https://www.w3.org/TR/webauthn-2/#sctn-extensions">Webauthn extensions</a>
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-defined-extensions">CTAP
   *     extensions</a>
   */
  public BasicWebAuthnClient(Ctap2Session session, List<Extension> extensions)
      throws IOException, CommandException {
    this.ctap = session;
    this.extensions = extensions;

    Ctap2Session.InfoData info = ctap.getInfo();

    Map<String, ?> options = info.getOptions();

    final Boolean optionClientPin = (Boolean) options.get(OPTION_CLIENT_PIN);
    pinSupported = optionClientPin != null;
    pinConfigured = Boolean.TRUE.equals(optionClientPin);

    final Boolean optionBioEnroll = (Boolean) options.get(OPTION_BIO_ENROLLMENT);
    bioEnrollSupported = optionBioEnroll != null;
    bioEnrollConfigured = Boolean.TRUE.equals(optionBioEnroll);

    this.clientPin =
        new ClientPin(ctap, getPreferredPinUvAuthProtocol(info.getPinUvAuthProtocols()));

    Boolean uv = (Boolean) options.get(OPTION_USER_VERIFICATION);
    uvSupported = uv != null;
    uvConfigured = uvSupported && uv;
    rkSupported = Boolean.TRUE.equals(options.get(OPTION_RESIDENT_KEY));

    enterpriseAttestationSupported = Boolean.TRUE.equals(options.get(OPTION_EP));
  }

  @Override
  public void close() throws IOException {
    ctap.close();
  }

  public UserAgentConfiguration getUserAgentConfiguration() {
    return userAgentConfiguration;
  }

  /**
   * Create a new WebAuthn credential.
   *
   * <p>PIN is always required if a PIN is configured.
   *
   * @param clientDataJson The UTF-8 encoded ClientData JSON object.
   * @param options The options for creating the credential.
   * @param effectiveDomain The effective domain for the request, which is used to validate the RP
   *     ID against.
   * @param pin If needed, the PIN to authorize the credential creation.
   * @param state If needed, the state to provide control over the ongoing operation
   * @return A WebAuthn public key credential.
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication in the protocol layer
   * @throws ClientError A higher level error
   */
  public PublicKeyCredential makeCredential(
      byte[] clientDataJson,
      PublicKeyCredentialCreationOptions options,
      String effectiveDomain,
      @Nullable char[] pin,
      @Nullable Integer enterpriseAttestation,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {
    byte[] clientDataHash = Utils.hash(clientDataJson);

    try {
      Pair<Ctap2Session.CredentialData, ClientExtensionResults> result =
          ctapMakeCredential(
              clientDataHash, options, effectiveDomain, pin, enterpriseAttestation, state);
      final Ctap2Session.CredentialData credential = result.first;
      final ClientExtensionResults clientExtensionResults = result.second;

      final AttestationObject attestationObject = AttestationObject.fromCredential(credential);

      AuthenticatorAttestationResponse response =
          new AuthenticatorAttestationResponse(
              clientDataJson, ctap.getCachedInfo().getTransports(), attestationObject);

      return new PublicKeyCredential(
          Objects.requireNonNull(
                  attestationObject.getAuthenticatorData().getAttestedCredentialData())
              .getCredentialId(),
          response,
          clientExtensionResults);
    } catch (CtapException e) {
      if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
        throw new PinInvalidClientError(e, clientPin.getPinRetries().getCount());
      }
      if (e.getCtapError() == CtapException.ERR_UV_INVALID) {
        throw new UvInvalidClientError(e, clientPin.getUvRetries());
      }
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Create a new WebAuthn credential.
   *
   * <p>PIN is always required if a PIN is configured.
   *
   * @param clientDataHash Hash of ClientData JSON object.
   * @param options The options for creating the credential.
   * @param effectiveDomain The effective domain for the request, which is used to validate the RP
   *     ID against.
   * @param pin If needed, the PIN to authorize the credential creation.
   * @param state If needed, the state to provide control over the ongoing operation
   * @return A WebAuthn public key credential.
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication in the protocol layer
   * @throws ClientError A higher level error
   */
  public PublicKeyCredential makeCredentialWithHash(
      byte[] clientDataHash,
      PublicKeyCredentialCreationOptions options,
      String effectiveDomain,
      @Nullable char[] pin,
      @Nullable Integer enterpriseAttestation,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {

    try {
      Pair<Ctap2Session.CredentialData, ClientExtensionResults> result =
          ctapMakeCredential(
              clientDataHash, options, effectiveDomain, pin, enterpriseAttestation, state);
      final Ctap2Session.CredentialData credential = result.first;
      final ClientExtensionResults clientExtensionResults = result.second;

      final AttestationObject attestationObject = AttestationObject.fromCredential(credential);

      AuthenticatorAttestationResponse response =
          new AuthenticatorAttestationResponse(
              new byte[0], ctap.getCachedInfo().getTransports(), attestationObject);

      return new PublicKeyCredential(
          Objects.requireNonNull(
                  attestationObject.getAuthenticatorData().getAttestedCredentialData())
              .getCredentialId(),
          response,
          clientExtensionResults);
    } catch (CtapException e) {
      if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
        throw new PinInvalidClientError(e, clientPin.getPinRetries().getCount());
      }
      if (e.getCtapError() == CtapException.ERR_UV_INVALID) {
        throw new UvInvalidClientError(e, clientPin.getUvRetries());
      }
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Authenticate an existing WebAuthn credential. PIN is required if UV is "required", or if UV is
   * "preferred" and a PIN is configured. If no allowCredentials list is provided (which is the case
   * for a passwordless flow) the Authenticator may contain multiple discoverable credentials for
   * the given RP. In such cases MultipleAssertionsAvailable will be thrown, and can be handled to
   * select an assertion.
   *
   * @param clientDataJson The UTF-8 encoded ClientData JSON object.
   * @param options The options for authenticating the credential.
   * @param effectiveDomain The effective domain for the request, which is used to validate the RP
   *     ID against.
   * @param pin If needed, the PIN to authorize the credential creation.
   * @param state If needed, the state to provide control over the ongoing operation
   * @return Webauthn public key credential with assertion response data.
   * @throws MultipleAssertionsAvailable In case of multiple assertions, catch this to make a
   *     selection and get the result.
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication in the protocol layer
   * @throws ClientError A higher level error
   */
  public PublicKeyCredential getAssertion(
      byte[] clientDataJson,
      PublicKeyCredentialRequestOptions options,
      String effectiveDomain,
      @Nullable char[] pin,
      @Nullable CommandState state)
      throws MultipleAssertionsAvailable, IOException, CommandException, ClientError {
    byte[] clientDataHash = Utils.hash(clientDataJson);
    try {
      final List<Pair<Ctap2Session.AssertionData, ClientExtensionResults>> results =
          ctapGetAssertions(clientDataHash, options, effectiveDomain, pin, state);

      final List<PublicKeyCredentialDescriptor> allowCredentials =
          removeUnsupportedCredentials(options.getAllowCredentials());

      if (results.size() == 1) {
        final Ctap2Session.AssertionData assertion = results.get(0).first;
        final ClientExtensionResults clientExtensionResults = results.get(0).second;

        return PublicKeyCredential.fromAssertion(
            assertion, clientDataJson, allowCredentials, clientExtensionResults);
      } else {
        throw new MultipleAssertionsAvailable(clientDataJson, results);
      }

    } catch (CtapException e) {
      if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
        throw new PinInvalidClientError(e, clientPin.getPinRetries().getCount());
      }
      if (e.getCtapError() == CtapException.ERR_UV_INVALID) {
        throw new UvInvalidClientError(e, clientPin.getUvRetries());
      }
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Authenticate an existing WebAuthn credential. PIN is required if UV is "required", or if UV is
   * "preferred" and a PIN is configured. If no allowCredentials list is provided (which is the case
   * for a passwordless flow) the Authenticator may contain multiple discoverable credentials for
   * the given RP. In such cases MultipleAssertionsAvailable will be thrown, and can be handled to
   * select an assertion.
   *
   * @param clientDataHash Hash of ClientData JSON object.
   * @param options The options for authenticating the credential.
   * @param effectiveDomain The effective domain for the request, which is used to validate the RP
   *     ID against.
   * @param pin If needed, the PIN to authorize the credential creation.
   * @param state If needed, the state to provide control over the ongoing operation
   * @return Webauthn public key credential with assertion response data.
   * @throws MultipleAssertionsAvailable In case of multiple assertions, catch this to make a
   *     selection and get the result.
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication in the protocol layer
   * @throws ClientError A higher level error
   */
  public PublicKeyCredential getAssertionWithHash(
      byte[] clientDataHash,
      PublicKeyCredentialRequestOptions options,
      String effectiveDomain,
      @Nullable char[] pin,
      @Nullable CommandState state)
      throws MultipleAssertionsAvailable, IOException, CommandException, ClientError {
    try {
      final List<Pair<Ctap2Session.AssertionData, ClientExtensionResults>> results =
          ctapGetAssertions(clientDataHash, options, effectiveDomain, pin, state);

      final List<PublicKeyCredentialDescriptor> allowCredentials =
          removeUnsupportedCredentials(options.getAllowCredentials());

      if (results.size() == 1) {
        final Ctap2Session.AssertionData assertion = results.get(0).first;
        final ClientExtensionResults clientExtensionResults = results.get(0).second;

        return PublicKeyCredential.fromAssertion(
            assertion, new byte[0], allowCredentials, clientExtensionResults);
      } else {
        throw new MultipleAssertionsAvailable(new byte[0], results);
      }

    } catch (CtapException e) {
      if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
        throw new PinInvalidClientError(e, clientPin.getPinRetries().getCount());
      }
      if (e.getCtapError() == CtapException.ERR_UV_INVALID) {
        throw new UvInvalidClientError(e, clientPin.getUvRetries());
      }
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Check if the Authenticator supports external PIN.
   *
   * @return If PIN is supported.
   */
  public boolean isPinSupported() {
    return pinSupported;
  }

  /**
   * Check if the Authenticator has been configured with a PIN.
   *
   * @return If a PIN is configured.
   */
  public boolean isPinConfigured() {
    return pinConfigured;
  }

  /**
   * Check if the Authenticator supports Enterprise Attestation feature.
   *
   * @return true if the authenticator is enterprise attestation capable and enterprise attestation
   *     is enabled.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-feature-descriptions-enterp-attstn">Enterprise
   *     Attestation</a>
   */
  public boolean isEnterpriseAttestationSupported() {
    return enterpriseAttestationSupported;
  }

  /**
   * Set the PIN for an Authenticator which supports PIN, but doesn't have one configured.
   *
   * @param pin The PIN to set.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @throws ClientError A higher level error.
   */
  public void setPin(char[] pin) throws IOException, CommandException, ClientError {
    if (!pinSupported) {
      throw new ClientError(ClientError.Code.BAD_REQUEST, "PIN is not supported on this device");
    }
    if (pinConfigured) {
      throw new ClientError(
          ClientError.Code.BAD_REQUEST, "A PIN is already configured on this device");
    }
    try {
      clientPin.setPin(pin);
      pinConfigured = true;
    } catch (CtapException e) {
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Change the PIN for an Authenticator which already has a PIN configured.
   *
   * @param currentPin The current PIN, to authorize the action.
   * @param newPin The new PIN to set.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @throws ClientError A higher level error.
   */
  public void changePin(char[] currentPin, char[] newPin)
      throws IOException, CommandException, ClientError {
    if (!pinSupported) {
      throw new ClientError(ClientError.Code.BAD_REQUEST, "PIN is not supported on this device");
    }
    if (!pinConfigured) {
      throw new ClientError(
          ClientError.Code.BAD_REQUEST, "No PIN currently configured on this device");
    }
    try {
      clientPin.changePin(currentPin, newPin);
    } catch (CtapException e) {
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Return an object that provides management of resident key type credentials stored on a YubiKey
   *
   * @param pin The configured PIN
   * @return Credential manager
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @throws ClientError A higher level error.
   */
  public CredentialManager getCredentialManager(char[] pin)
      throws IOException, CommandException, ClientError {
    if (!pinConfigured) {
      throw new ClientError(
          ClientError.Code.BAD_REQUEST, "No PIN currently configured on this device");
    }
    try {
      return new CredentialManager(
          new CredentialManagement(
              ctap,
              clientPin.getPinUvAuth(),
              clientPin.getPinToken(pin, ClientPin.PIN_PERMISSION_CM, null)));
    } catch (CtapException e) {
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Create a new WebAuthn credential.
   *
   * <p>This method is used internally in YubiKit and is not part of the public API. It may be
   * changed or removed at any time.
   *
   * <p>PIN is always required if a PIN is configured.
   *
   * @param clientDataHash Hash of client data.
   * @param options The options for creating the credential.
   * @param effectiveDomain The effective domain for the request, which is used to validate the RP
   *     ID against.
   * @param pin If needed, the PIN to authorize the credential creation.
   * @param state If needed, the state to provide control over the ongoing operation
   * @return A pair of credential data and client extension results.
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication in the protocol layer
   * @throws ClientError A higher level error
   */
  @SuppressWarnings("unchecked")
  protected Pair<Ctap2Session.CredentialData, ClientExtensionResults> ctapMakeCredential(
      byte[] clientDataHash,
      PublicKeyCredentialCreationOptions options,
      String effectiveDomain,
      @Nullable char[] pin,
      @Nullable Integer enterpriseAttestation,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {

    final SerializationType serializationType = SerializationType.CBOR;

    Map<String, ?> rp = options.getRp().toMap(serializationType);
    String rpId = options.getRp().getId();
    if (rpId == null) {
      ((Map<String, Object>) rp).put("id", effectiveDomain);
    } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
      throw new ClientError(
          ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
    }

    int permissions = ClientPin.PIN_PERMISSION_MC;
    if (!options.getExcludeCredentials().isEmpty()) {
      permissions |= ClientPin.PIN_PERMISSION_GA;
    }
    List<Extension.RegistrationProcessor> registrationProcessors = new ArrayList<>();
    for (Extension extension : extensions) {
      Extension.RegistrationProcessor processor =
          extension.makeCredential(ctap, options, clientPin.getPinUvAuth());
      if (processor != null) {
        registrationProcessors.add(processor);
        permissions |= processor.getPermissions();
      }
    }

    AuthenticatorSelectionCriteria authenticatorSelection = options.getAuthenticatorSelection();
    String userVerification =
        authenticatorSelection != null ? authenticatorSelection.getUserVerification() : null;
    String selectionResidentKey =
        authenticatorSelection != null
            ? authenticatorSelection.getResidentKey()
            : ResidentKeyRequirement.PREFERRED;
    boolean rk =
        ResidentKeyRequirement.REQUIRED.equals(selectionResidentKey)
            || (ResidentKeyRequirement.PREFERRED.equals(selectionResidentKey) && rkSupported);

    final AuthParams authParams = getAuthParams(pin, userVerification, permissions, rpId, state);

    Map<String, Boolean> ctapOptions;
    if (!(rk || authParams.internalUv)) {
      ctapOptions = null;
    } else {
      ctapOptions = new HashMap<>();
      if (rk) {
        if (!rkSupported) {
          throw new ClientError(
              ClientError.Code.CONFIGURATION_UNSUPPORTED, "Resident key not supported");
        }
        ctapOptions.put(OPTION_RESIDENT_KEY, true);
      }
      if (authParams.internalUv) {
        ctapOptions.put(OPTION_USER_VERIFICATION, true);
      }
    }

    HashMap<String, Object> authenticatorInputs = new HashMap<>();
    for (Extension.RegistrationProcessor processor : registrationProcessors) {
      authenticatorInputs.putAll(processor.getInput(authParams.pinToken));
    }

    final List<PublicKeyCredentialDescriptor> excludeCredentials =
        removeUnsupportedCredentials(options.getExcludeCredentials());

    PublicKeyCredentialDescriptor credToExclude =
        excludeCredentials != null
            ? Utils.filterCreds(
                ctap,
                rpId,
                excludeCredentials,
                effectiveDomain,
                clientPin.getPinUvAuth(),
                authParams.pinToken)
            : null;

    final Map<String, ?> user = options.getUser().toMap(serializationType);

    List<Map<String, ?>> pubKeyCredParams = new ArrayList<>();
    for (PublicKeyCredentialParameters param : options.getPubKeyCredParams()) {
      if (isPublicKeyCredentialTypeSupported(param.getType())) {
        pubKeyCredParams.add(param.toMap(serializationType));
      }
    }

    @Nullable Integer validatedEnterpriseAttestation = null;
    if (isEnterpriseAttestationSupported()
        && AttestationConveyancePreference.ENTERPRISE.equals(options.getAttestation())
        && userAgentConfiguration.supportsEpForRpId(rpId)
        && enterpriseAttestation != null
        && (enterpriseAttestation == 1 || enterpriseAttestation == 2)) {
      validatedEnterpriseAttestation = enterpriseAttestation;
    }

    byte[] pinUvAuthParam =
        authParams.pinToken != null
            ? clientPin.getPinUvAuth().authenticate(authParams.pinToken, clientDataHash)
            : null;
    Integer pinUvAuthProtocolVersion =
        authParams.pinToken != null ? clientPin.getPinUvAuth().getVersion() : null;

    Ctap2Session.CredentialData credentialData =
        ctap.makeCredential(
            clientDataHash,
            rp,
            user,
            pubKeyCredParams,
            credToExclude != null
                ? Utils.getCredentialList(Collections.singletonList(credToExclude))
                : null,
            authenticatorInputs,
            ctapOptions,
            pinUvAuthParam,
            pinUvAuthProtocolVersion,
            validatedEnterpriseAttestation,
            state);

    ClientExtensionResults clientExtensionResults = new ClientExtensionResults();
    for (Extension.RegistrationProcessor processor : registrationProcessors) {
      AttestationObject attestationObject = AttestationObject.fromCredential(credentialData);
      clientExtensionResults.add(processor.getOutput(attestationObject, authParams.pinToken));
    }
    return new Pair<>(credentialData, clientExtensionResults);
  }

  /**
   * Authenticate an existing WebAuthn credential.
   *
   * <p>This method is used internally in YubiKit and is not part of the public API. It may be
   * changed or removed at any time.
   *
   * <p>PIN is required if UV is "required", or if UV is "preferred" and a PIN is configured. If no
   * allowCredentials list is provided (which is the case for a passwordless flow) the Authenticator
   * may contain multiple discoverable credentials for the given RP. In such cases
   * MultipleAssertionsAvailable will be thrown, and can be handled to select an assertion.
   *
   * @param clientDataHash Hash of client data.
   * @param options The options for authenticating the credential.
   * @param effectiveDomain The effective domain for the request, which is used to validate the RP
   *     ID against.
   * @param pin If needed, the PIN to authorize the credential creation.
   * @param state If needed, the state to provide control over the ongoing operation
   * @return List of pairs containing assertion response data and client extension results.
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication in the protocol layer
   * @throws ClientError A higher level error
   */
  protected List<Pair<Ctap2Session.AssertionData, ClientExtensionResults>> ctapGetAssertions(
      byte[] clientDataHash,
      PublicKeyCredentialRequestOptions options,
      String effectiveDomain,
      @Nullable char[] pin,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {
    String rpId = options.getRpId();
    if (rpId == null) {
      rpId = effectiveDomain;
    } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
      throw new ClientError(
          ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
    }

    final List<PublicKeyCredentialDescriptor> allowCredentials =
        removeUnsupportedCredentials(options.getAllowCredentials());

    int permissions = ClientPin.PIN_PERMISSION_GA;
    List<Extension.AuthenticationProcessor> authenticationProcessors = new ArrayList<>();
    for (Extension extension : extensions) {
      Extension.AuthenticationProcessor processor =
          extension.getAssertion(ctap, options, clientPin.getPinUvAuth());
      if (processor != null) {
        authenticationProcessors.add(processor);
        permissions |= processor.getPermissions();
      }
    }

    final String userVerification = options.getUserVerification();
    final AuthParams authParams = getAuthParams(pin, userVerification, permissions, rpId, state);

    final boolean hasValidAllowList = allowCredentials != null && !allowCredentials.isEmpty();
    PublicKeyCredentialDescriptor selectedCred =
        hasValidAllowList
            ? Utils.filterCreds(
                ctap,
                rpId,
                allowCredentials,
                effectiveDomain,
                clientPin.getPinUvAuth(),
                authParams.pinToken)
            : null;

    if (hasValidAllowList && selectedCred == null) {
      // We still need to send a dummy value if there was an allowCredentials list but no matches
      // were found.
      selectedCred =
          new PublicKeyCredentialDescriptor(allowCredentials.get(0).getType(), new byte[] {0x00});
    }

    HashMap<String, Object> authenticatorInputs = new HashMap<>();
    for (Extension.AuthenticationProcessor processor : authenticationProcessors) {
      authenticatorInputs.putAll(processor.getInput(selectedCred, authParams.pinToken));
    }

    Map<String, Boolean> ctapOptions =
        authParams.internalUv ? Collections.singletonMap(OPTION_USER_VERIFICATION, true) : null;

    try {

      byte[] pinUvAuthParam =
          authParams.pinToken != null
              ? clientPin.getPinUvAuth().authenticate(authParams.pinToken, clientDataHash)
              : null;
      Integer pinUvAuthProtocolVersion =
          authParams.pinToken != null ? clientPin.getPinUvAuth().getVersion() : null;

      List<Ctap2Session.AssertionData> assertions =
          ctap.getAssertions(
              rpId,
              clientDataHash,
              selectedCred != null
                  ? Utils.getCredentialList(Collections.singletonList(selectedCred))
                  : null,
              authenticatorInputs,
              ctapOptions,
              pinUvAuthParam,
              pinUvAuthProtocolVersion,
              state);

      List<Pair<Ctap2Session.AssertionData, ClientExtensionResults>> result = new ArrayList<>();
      for (final Ctap2Session.AssertionData assertionData : assertions) {
        ClientExtensionResults clientExtensionResults = new ClientExtensionResults();
        for (Extension.AuthenticationProcessor processor : authenticationProcessors) {
          clientExtensionResults.add(processor.getOutput(assertionData, authParams.pinToken));
        }
        result.add(new Pair<>(assertionData, clientExtensionResults));
      }
      return result;

    } catch (CtapException e) {
      if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
        throw new PinInvalidClientError(e, clientPin.getPinRetries().getCount());
      }
      if (e.getCtapError() == CtapException.ERR_UV_INVALID) {
        throw new UvInvalidClientError(e, clientPin.getUvRetries());
      }
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Determines if user verification (UV) should be used based on authenticator info, user
   * verification requirement, and permissions.
   */
  private boolean shouldUseUv(
      Ctap2Session.InfoData info, @Nullable String userVerification, int permissions)
      throws ClientError {
    Map<String, ?> options = info.getOptions();

    // is any user verification supported by the authenticator?
    boolean supportsUv = uvSupported || pinSupported || bioEnrollSupported;
    // is any user verification configured by the authenticator?
    boolean hasUvConfigured = uvConfigured || pinConfigured || bioEnrollConfigured;

    boolean mc = (ClientPin.PIN_PERMISSION_MC & permissions) != 0;
    int additionalPerms =
        permissions & ~(ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA);

    if (UserVerificationRequirement.REQUIRED.equals(userVerification)
        || ((UserVerificationRequirement.PREFERRED.equals(userVerification)
                || userVerification == null)
            && supportsUv)
        || ((UserVerificationRequirement.DISCOURAGED.equals(userVerification)) && pinConfigured)
        || Boolean.TRUE.equals(options.get(OPTION_ALWAYS_UV))) {
      if (!hasUvConfigured) {
        throw new ClientError(
            ClientError.Code.CONFIGURATION_UNSUPPORTED,
            "User verification not configured/supported");
      }
      return true;
    }
    if (mc && hasUvConfigured && !Boolean.TRUE.equals(options.get(OPTION_MC_UV_NOT_RQD))) {
      return true;
    }
    return hasUvConfigured && additionalPerms != 0;
  }

  @Nullable
  private byte[] getToken(
      @Nullable char[] pin,
      int permissions,
      @Nullable String rpId,
      boolean allowInternalUv,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {
    final Ctap2Session.InfoData info = ctap.getCachedInfo();

    if (uvConfigured && pin == null) {
      if (ClientPin.isTokenSupported(info)) {
        if (clientPin.getUvRetries() > 0) {
          return clientPin.getUvToken(permissions, rpId, state);
        } else if (allowInternalUv) {
          return null;
        }
      }
      return null;
    }

    if (pinConfigured) {
      if (pin == null) {
        throw new PinRequiredClientError();
      }
      return clientPin.getPinToken(pin, permissions, rpId);
    }

    throw new ClientError(
        ClientError.Code.CONFIGURATION_UNSUPPORTED, "User verification not configured");
  }

  private AuthParams getAuthParams(
      @Nullable char[] pin,
      @Nullable String userVerification,
      int permissions,
      @Nullable String rpId,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {
    Ctap2Session.InfoData info = ctap.getCachedInfo();

    byte[] pinToken = null;
    boolean internalUv = false;

    if (shouldUseUv(info, userVerification, permissions)) {
      boolean allowInternalUv =
          (permissions & ~(ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA)) == 0;
      pinToken = getToken(pin, permissions, rpId, allowInternalUv, state);
      if (pinToken == null) {
        internalUv = true;
      }
    }

    return new AuthParams(pinToken, internalUv);
  }

  /**
   * Calculates the preferred pinUvAuth protocol for authenticator provided list. Returns
   * PinUvAuthDummyProtocol if the authenticator does not support any of the SDK supported
   * protocols.
   */
  private PinUvAuthProtocol getPreferredPinUvAuthProtocol(List<Integer> pinUvAuthProtocols) {
    if (pinSupported) {
      for (int protocol : pinUvAuthProtocols) {
        if (protocol == PinUvAuthProtocolV1.VERSION) {
          return new PinUvAuthProtocolV1();
        }

        if (protocol == PinUvAuthProtocolV2.VERSION) {
          return new PinUvAuthProtocolV2();
        }
      }
    }

    return new PinUvAuthDummyProtocol();
  }

  private static boolean isPublicKeyCredentialTypeSupported(String type) {
    return PUBLIC_KEY.equals(type);
  }

  /**
   * @return new list containing only descriptors with valid {@code PublicKeyCredentialType} type
   */
  @Nullable
  private static List<PublicKeyCredentialDescriptor> removeUnsupportedCredentials(
      @Nullable List<PublicKeyCredentialDescriptor> descriptors) {
    if (descriptors == null || descriptors.isEmpty()) {
      return descriptors;
    }

    final List<PublicKeyCredentialDescriptor> list = new ArrayList<>();
    for (PublicKeyCredentialDescriptor credential : descriptors) {
      if (isPublicKeyCredentialTypeSupported(credential.getType())) {
        list.add(credential);
      }
    }
    return list;
  }

  private static final List<Extension> defaultExtensions =
      Arrays.asList(
          new CredPropsExtension(),
          new CredBlobExtension(),
          new CredProtectExtension(),
          new HmacSecretExtension(),
          new MinPinLengthExtension(),
          new LargeBlobExtension());

  static class Utils {

    /**
     * @return first acceptable credential from the list available on the authenticator
     */
    @Nullable
    static PublicKeyCredentialDescriptor filterCreds(
        Ctap2Session ctap,
        @Nullable String rpId,
        List<PublicKeyCredentialDescriptor> descriptors,
        String effectiveDomain,
        @Nullable PinUvAuthProtocol pinUvAuthProtocol,
        @Nullable byte[] pinUvAuthToken)
        throws IOException, CommandException, ClientError {

      if (rpId == null) {
        rpId = effectiveDomain;
      } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
        throw new ClientError(
            ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
      }

      List<PublicKeyCredentialDescriptor> creds;

      // filter out credential IDs which are too long
      Ctap2Session.InfoData info = ctap.getCachedInfo();
      Integer maxCredIdLength = info.getMaxCredentialIdLength();
      if (maxCredIdLength != null) {
        creds = new ArrayList<>();
        for (PublicKeyCredentialDescriptor desc : descriptors) {
          if (desc.getId().length <= maxCredIdLength) {
            creds.add(desc);
          }
        }
      } else {
        creds = new ArrayList<>(descriptors);
      }

      int maxCreds =
          info.getMaxCredentialCountInList() != null ? info.getMaxCredentialCountInList() : 1;

      byte[] clientDataHash = new byte[32];
      Arrays.fill(clientDataHash, (byte) 0x00);

      Map<String, Boolean> options = new HashMap<>();
      options.put("up", false);

      byte[] pinAuth = null;
      Integer pinUvAuthVersion = null;
      if (pinUvAuthToken != null && pinUvAuthProtocol != null) {
        pinAuth = pinUvAuthProtocol.authenticate(pinUvAuthToken, clientDataHash);
        pinUvAuthVersion = pinUvAuthProtocol.getVersion();
      } else {
        options.put("uv", true);
      }

      while (!creds.isEmpty()) {
        Logger.trace(logger, "Pre-flighting list of {} credentials", creds.size());
        final List<PublicKeyCredentialDescriptor> chunk =
            creds.subList(0, Math.min(maxCreds, creds.size()));
        try {
          List<Ctap2Session.AssertionData> assertions =
              ctap.getAssertions(
                  rpId,
                  clientDataHash,
                  getCredentialList(chunk),
                  null,
                  options,
                  pinAuth,
                  pinUvAuthVersion,
                  null);

          if (chunk.size() == 1) {
            return chunk.get(0);
          }

          final Ctap2Session.AssertionData assertion = assertions.get(0);
          final byte[] id = assertion.getCredentialId(null);

          return new PublicKeyCredentialDescriptor(PUBLIC_KEY, id);

        } catch (CtapException ctapException) {
          final byte ctapError = ctapException.getCtapError();
          if (ctapError == CtapException.ERR_NO_CREDENTIALS) {
            Logger.trace(logger, "No credentials found in chunk");
            chunk.clear();
            continue;
          } else if (ctapError == CtapException.ERR_REQUEST_TOO_LARGE) {
            maxCreds--;
            Logger.trace(logger, "Chunk request was too large, retrying with {} creds", maxCreds);
            if (maxCreds == 0) {
              throw ctapException;
            }
            continue;
          }

          throw ctapException;
        }
      }

      return null;
    }

    /**
     * @return new list of Credential descriptors for CBOR serialization.
     */
    @Nullable
    static List<Map<String, ?>> getCredentialList(
        @Nullable List<PublicKeyCredentialDescriptor> descriptors) {
      if (descriptors == null || descriptors.isEmpty()) {
        return null;
      }
      List<Map<String, ?>> creds = new ArrayList<>();
      for (PublicKeyCredentialDescriptor descriptor : descriptors) {
        creds.add(descriptor.toMap(SerializationType.CBOR));
      }
      return creds;
    }

    /**
     * Return SHA-256 hash of the provided input
     *
     * @param message The hash input
     * @return SHA-256 of the input
     */
    static byte[] hash(byte[] message) {
      try {
        return MessageDigest.getInstance("SHA-256").digest(message);
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }
    }
  }
}

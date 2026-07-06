/*
 * Copyright (C) 2020-2026 Yubico.
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
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider;
import com.yubico.yubikit.fido.client.extensions.CredBlobExtension;
import com.yubico.yubikit.fido.client.extensions.CredPropsExtension;
import com.yubico.yubikit.fido.client.extensions.CredProtectExtension;
import com.yubico.yubikit.fido.client.extensions.Extension;
import com.yubico.yubikit.fido.client.extensions.ExtensionConfigurationException;
import com.yubico.yubikit.fido.client.extensions.ExtensionNotSupportedException;
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
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * WebAuthn client implementation which wraps a YubiKeySession.
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
public class Ctap2Client implements WebAuthnClient {
  static final String OPTION_CLIENT_PIN = "clientPin";
  static final String OPTION_USER_VERIFICATION = "uv";
  static final String OPTION_USER_PRESENCE = "up";
  static final String OPTION_BIO_ENROLLMENT = "bioEnroll";
  static final String OPTION_RESIDENT_KEY = "rk";
  static final String OPTION_EP = "ep";
  static final String OPTION_ALWAYS_UV = "alwaysUv";
  static final String OPTION_MC_UV_NOT_RQD = "makeCredUvNotRqd";

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

  private static final Logger logger = LoggerFactory.getLogger(Ctap2Client.class);

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
    private final byte @Nullable [] pinToken;
    private final boolean internalUv;

    AuthParams(byte @Nullable [] pinToken, boolean internalUv) {
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
   * @see <a href="https://www.w3.org/TR/webauthn-3/#webauthn-client">Webauthn client</a>
   * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">Webauthn extensions</a>
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-defined-extensions">CTAP
   *     extensions</a>
   */
  public Ctap2Client(Ctap2Session session) throws IOException, CommandException {
    this(session, null);
  }

  /**
   * Create a new Webauthn client.
   *
   * <p>This client will only process provided extensions.
   *
   * @param session CTAP2 session
   * @param extensions List of extensions or null to use default extensions
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication in the protocol layer
   * @see <a href="https://www.w3.org/TR/webauthn-3/#webauthn-client">Webauthn client</a>
   * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">Webauthn extensions</a>
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-defined-extensions">CTAP
   *     extensions</a>
   */
  public Ctap2Client(Ctap2Session session, @Nullable List<Extension> extensions)
      throws IOException, CommandException {
    this.ctap = session;
    this.extensions = extensions != null ? extensions : defaultExtensions;

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

  public Ctap2Session getSession() {
    return ctap;
  }

  /**
   * Create a new WebAuthn credential.
   *
   * @return A WebAuthn public key credential.
   * @throws IOException A communication error in the transport layer
   * @throws CommandException A communication in the protocol layer
   * @throws ClientError A higher level error
   */
  @Override
  public PublicKeyCredential makeCredential(
      ClientDataProvider clientData,
      PublicKeyCredentialCreationOptions options,
      String effectiveDomain,
      char @Nullable [] pin,
      @Nullable Integer enterpriseAttestation,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {

    try {
      Pair<Ctap2Session.CredentialData, ClientExtensionResults> result =
          ctapMakeCredential(
              clientData.getHash(), options, effectiveDomain, pin, enterpriseAttestation, state);
      final Ctap2Session.CredentialData credential = result.first;
      final ClientExtensionResults clientExtensionResults = result.second;

      final AttestationObject attestationObject = AttestationObject.fromCredential(credential);

      AuthenticatorAttestationResponse response =
          new AuthenticatorAttestationResponse(
              clientData.getClientDataJson(),
              ctap.getCachedInfo().getTransports(),
              attestationObject);

      return new PublicKeyCredential(
          Objects.requireNonNull(
                  attestationObject.getAuthenticatorData().getAttestedCredentialData())
              .getCredentialId(),
          response,
          clientExtensionResults);
    } catch (CtapException e) {
      if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
        throw new AuthInvalidClientError(
            e, AuthInvalidClientError.AuthType.PIN, getSafePinRetryCount());
      }
      if (e.getCtapError() == CtapException.ERR_UV_INVALID) {
        throw new AuthInvalidClientError(
            e, AuthInvalidClientError.AuthType.UV, getSafeUvRetryCount());
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
   * @param clientData The {@link ClientDataProvider} instance supplying client data for the
   *     request. If a provider that only supplies the hash is passed, the resulting credential will
   *     contain an empty clientDataJSON in the response.
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
      ClientDataProvider clientData,
      PublicKeyCredentialRequestOptions options,
      String effectiveDomain,
      char @Nullable [] pin,
      @Nullable CommandState state)
      throws MultipleAssertionsAvailable, IOException, CommandException, ClientError {
    try {
      final List<Pair<Ctap2Session.AssertionData, ClientExtensionResults>> results =
          ctapGetAssertions(clientData.getHash(), options, effectiveDomain, pin, state);

      final List<PublicKeyCredentialDescriptor> allowCredentials = options.getAllowCredentials();

      if (results.size() == 1) {
        final Ctap2Session.AssertionData assertion = results.get(0).first;
        final ClientExtensionResults clientExtensionResults = results.get(0).second;

        return PublicKeyCredential.fromAssertion(
            assertion, clientData.getClientDataJson(), allowCredentials, clientExtensionResults);
      } else {
        throw new MultipleAssertionsAvailable(clientData.getClientDataJson(), results);
      }

    } catch (CtapException e) {
      if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
        throw new AuthInvalidClientError(
            e, AuthInvalidClientError.AuthType.PIN, getSafePinRetryCount());
      }
      if (e.getCtapError() == CtapException.ERR_UV_INVALID) {
        throw new AuthInvalidClientError(
            e, AuthInvalidClientError.AuthType.UV, getSafeUvRetryCount());
      }
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Check if the Authenticator supports PIN.
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
   *     href="https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-feature-descriptions-enterp-attstn">Enterprise
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
      if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
        throw new AuthInvalidClientError(
            e, AuthInvalidClientError.AuthType.PIN, getSafePinRetryCount());
      }
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
      char @Nullable [] pin,
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

    final List<PublicKeyCredentialDescriptor> excludeCredentials = options.getExcludeCredentials();

    int permissions =
        ClientPin.PIN_PERMISSION_MC
            | (excludeCredentials.isEmpty() ? 0 : ClientPin.PIN_PERMISSION_GA);
    List<Extension.RegistrationProcessor> registrationProcessors = new ArrayList<>();
    for (Extension extension : extensions) {
      try {
        Extension.RegistrationProcessor processor =
            extension.makeCredential(ctap, options, clientPin.getPinUvAuth());
        if (processor != null) {
          registrationProcessors.add(processor);
          permissions |= processor.getPermissions();
        }
      } catch (RuntimeException e) {
        handleExtensionFailure(e);
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

    // Validate before getAuthParams (which may trigger user verification) so a required-but-
    // unsupported resident key fails fast instead of prompting for a PIN and then erroring.
    if (rk && !rkSupported) {
      throw new ClientError(
          ClientError.Code.CONFIGURATION_UNSUPPORTED, "Resident key not supported");
    }

    final AuthParams authParams =
        getAuthParams(pin, userVerification, permissions, rpId, rk, state);

    Map<String, Boolean> ctapOptions;
    if (!(rk || authParams.internalUv)) {
      ctapOptions = null;
    } else {
      ctapOptions = new HashMap<>();
      if (rk) {
        ctapOptions.put(OPTION_RESIDENT_KEY, true);
      }
      if (authParams.internalUv) {
        ctapOptions.put(OPTION_USER_VERIFICATION, true);
      }
    }

    HashMap<String, Object> authenticatorInputs = new HashMap<>();
    for (Extension.RegistrationProcessor processor : registrationProcessors) {
      try {
        authenticatorInputs.putAll(processor.getInput(authParams.pinToken));
      } catch (RuntimeException e) {
        handleExtensionFailure(e);
      }
    }

    final PublicKeyCredentialDescriptor credToExclude =
        excludeCredentials.isEmpty()
            ? null
            : Utils.filterCreds(
                ctap,
                rpId,
                excludeCredentials,
                effectiveDomain,
                clientPin.getPinUvAuth(),
                authParams.pinToken);

    final Map<String, ?> user = options.getUser().toMap(serializationType);

    List<Map<String, ?>> pubKeyCredParams = new ArrayList<>();
    for (PublicKeyCredentialParameters param : options.getPubKeyCredParams()) {
      if (isPublicKeyCredentialTypeSupported(param.getType())) {
        pubKeyCredParams.add(param.toMap(serializationType));
      }
    }

    Integer validatedEnterpriseAttestation = null;
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
    // Parse the attestation for extension-output processing. A parse failure is not
    // extension-specific (the authenticator returned an unparseable attestation) and is not caller
    // input, so it is surfaced as a typed ClientError rather than an untyped unchecked exception.
    // The attestation is mandatory to build the response, so a parse failure must abort the
    // ceremony;
    // continuing without extension outputs would only defer the crash. The public makeCredential()
    // parses it again to build the response; that re-parse cannot fail once this one succeeds.
    final AttestationObject attestationObject;
    try {
      attestationObject = AttestationObject.fromCredential(credentialData);
    } catch (RuntimeException e) {
      throw new ClientError(ClientError.Code.OTHER_ERROR, "Failed to parse attestation object", e);
    }
    for (Extension.RegistrationProcessor processor : registrationProcessors) {
      try {
        clientExtensionResults.add(processor.getOutput(attestationObject, authParams.pinToken));
      } catch (RuntimeException e) {
        handleExtensionFailure(e);
      }
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
      char @Nullable [] pin,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {
    String rpId = options.getRpId();
    if (rpId == null) {
      rpId = effectiveDomain;
    } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
      throw new ClientError(
          ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
    }
    final List<PublicKeyCredentialDescriptor> allowCredentials = options.getAllowCredentials();
    int permissions = ClientPin.PIN_PERMISSION_GA;
    List<Extension.AuthenticationProcessor> authenticationProcessors = new ArrayList<>();
    for (Extension extension : extensions) {
      try {
        Extension.AuthenticationProcessor processor =
            extension.getAssertion(ctap, options, clientPin.getPinUvAuth());
        if (processor != null) {
          authenticationProcessors.add(processor);
          permissions |= processor.getPermissions();
        }
      } catch (RuntimeException e) {
        handleExtensionFailure(e);
      }
    }

    final String userVerification = options.getUserVerification();
    // An empty allowList is a usernameless (discoverable) assertion: UV is needed so the
    // authenticator reveals user name/displayName for account selection.
    final AuthParams authParams =
        getAuthParams(pin, userVerification, permissions, rpId, allowCredentials.isEmpty(), state);

    PublicKeyCredentialDescriptor selectedCred =
        allowCredentials.isEmpty()
            ? null
            : Utils.filterCreds(
                ctap,
                rpId,
                allowCredentials,
                effectiveDomain,
                clientPin.getPinUvAuth(),
                authParams.pinToken);

    HashMap<String, Object> authenticatorInputs = new HashMap<>();
    for (Extension.AuthenticationProcessor processor : authenticationProcessors) {
      try {
        authenticatorInputs.putAll(processor.getInput(selectedCred, authParams.pinToken));
      } catch (RuntimeException e) {
        handleExtensionFailure(e);
      }
    }

    if (!allowCredentials.isEmpty() && selectedCred == null) {
      // We still need to send a dummy value if there was an allowCredentials list but no matches
      // were found.
      selectedCred =
          new PublicKeyCredentialDescriptor(allowCredentials.get(0).getType(), new byte[] {0x00});
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
          try {
            clientExtensionResults.add(processor.getOutput(assertionData, authParams.pinToken));
          } catch (RuntimeException e) {
            handleExtensionFailure(e);
          }
        }
        result.add(new Pair<>(assertionData, clientExtensionResults));
      }
      return result;

    } catch (CtapException e) {
      if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
        throw new AuthInvalidClientError(
            e, AuthInvalidClientError.AuthType.PIN, getSafePinRetryCount());
      }
      if (e.getCtapError() == CtapException.ERR_UV_INVALID) {
        throw new AuthInvalidClientError(
            e, AuthInvalidClientError.AuthType.UV, getSafeUvRetryCount());
      }
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Determines whether user verification should be used based on the authenticator's capabilities,
   * configuration, user verification requirement, and requested permissions.
   *
   * @param info The authenticator info containing capabilities and configuration.
   * @param userVerification The user verification requirement from the request (required,
   *     preferred, or discouraged).
   * @param permissions The requested permissions flags for the operation.
   * @return true if user verification should be used, false otherwise.
   * @throws ClientError If user verification is required but not configured or supported.
   */
  // Package-private (not private) so it can be unit-tested directly across the
  // userVerification × makeCredential/getAssertion × discoverable × makeCredUvNotRqd matrix.
  //
  // discoverable means the operation involves discoverable (resident) credentials: for
  // makeCredential it is rk=true; for getAssertion it is an empty allowList (usernameless).
  boolean shouldUseUv(
      Ctap2Session.InfoData info,
      @Nullable String userVerification,
      int permissions,
      boolean discoverable)
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
        || Boolean.TRUE.equals(options.get(OPTION_ALWAYS_UV))) {
      if (!hasUvConfigured) {
        throw new ClientError(
            ClientError.Code.CONFIGURATION_UNSUPPORTED,
            "User verification not configured/supported");
      }
      return true;
    }
    // Discoverable-credential operations on a UV-configured authenticator need UV even when
    // userVerification=discouraged:
    //  - makeCredential rk=true: the authenticator rejects resident-key creation without UV
    //    (CTAP2_ERR_PUAT_REQUIRED); makeCredUvNotRqd only exempts NON-discoverable creation.
    //  - getAssertion with an empty allowList: without UV the authenticator omits user name and
    //    displayName (single-factor privacy), leaving no way to present an account picker.
    if (discoverable && hasUvConfigured) {
      return true;
    }
    // Non-discoverable makeCredential needs UV unless makeCredUvNotRqd lets it skip.
    if (mc && hasUvConfigured && !Boolean.TRUE.equals(options.get(OPTION_MC_UV_NOT_RQD))) {
      return true;
    }
    return hasUvConfigured && additionalPerms != 0;
  }

  private byte @Nullable [] getToken(
      char @Nullable [] pin,
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
      char @Nullable [] pin,
      @Nullable String userVerification,
      int permissions,
      @Nullable String rpId,
      boolean discoverable,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {
    Ctap2Session.InfoData info = ctap.getCachedInfo();

    byte[] pinToken = null;
    boolean internalUv = false;

    if (shouldUseUv(info, userVerification, permissions, discoverable)) {
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

  /**
   * Handles a {@link RuntimeException} raised while processing a single client extension.
   *
   * <h2>Extension input contract</h2>
   *
   * Client extensions communicate their outcome with exactly two signals, so that one extension can
   * never silently corrupt or abort a ceremony it shouldn't:
   *
   * <ul>
   *   <li><b>Return {@code null} — ignore.</b> The extension does not apply and is skipped; the
   *       ceremony continues with the remaining extensions. This is the {@code SHOULD ignore} path
   *       of <a href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">WebAuthn §9</a> and
   *       covers: not requested; not supported by the authenticator; nothing to evaluate; an
   *       extension this client has no handler for (never dispatched, left ignorable for
   *       forward-compatibility); and malformed <em>authenticator</em> output (the device's fault,
   *       not the caller's). Note a recognized extension's unrecognized <em>value</em> (e.g. an
   *       unknown {@code credProtect} policy or {@code largeBlob} support) is a caller error and is
   *       surfaced, not ignored — see the enum-member rule below.
   *   <li><b>Throw — abort.</b> The ceremony fails with a {@link ClientError}. Reserved for a
   *       caller error or an explicitly-requested capability that cannot be satisfied (see below).
   * </ul>
   *
   * <p>Whether malformed <em>client</em> input is an error or is ignored is decided per member
   * kind, mirroring what a browser's WebIDL binding does before extension processing runs:
   *
   * <ul>
   *   <li><b>Missing a required member → error.</b> A {@code required} member that is absent is a
   *       {@code TypeError} at the binding (e.g. {@code prf.eval.first}, {@code
   *       hmacGetSecret.salt1}).
   *   <li><b>Wrong type on a dictionary or {@code BufferSource} member → error.</b> These
   *       correspond to WebIDL conversions that throw {@code TypeError} (e.g. a non-object {@code
   *       largeBlob}/{@code payment}/{@code prf}, or a non-string {@code credBlob}/{@code
   *       largeBlob.write}/prf salt).
   *   <li><b>Invalid encoding of a {@code BufferSource} member → error.</b> A well-typed string
   *       that is not valid base64url is undecodable and can never be correct, so it is surfaced
   *       (via {@link com.yubico.yubikit.core.internal.codec.Base64#fromUrlSafeString}) rather than
   *       silently dropped. This is intentionally stricter than §9.3's {@code SHOULD ignore},
   *       trading strict spec-leniency for SDK ergonomics (a bad value is a caller bug worth
   *       reporting).
   *   <li><b>Invalid value of an enum member → error.</b> {@code credProtect}'s {@code
   *       credentialProtectionPolicy} (one of the three defined policy strings) and {@code
   *       largeBlob}'s {@code support} ({@code "required"} or {@code "preferred"}) must be a
   *       recognized value; an unrecognized string or a non-string is surfaced rather than silently
   *       dropped. For {@code credProtect} the client maps the string to an integer, so silently
   *       dropping it would mint a credential without the requested protection. An absent (or
   *       {@code null}) member is "not requested" and ignored.
   *   <li><b>Wrong type on a boolean member → error.</b> Every recognized boolean client-input
   *       member is validated: a non-boolean value for {@code minPinLength}, {@code credProps},
   *       {@code payment.isPayment}, {@code getCredBlob}, {@code largeBlob.read}, {@code
   *       hmacCreateSecret}, or {@code enforceCredentialProtectionPolicy} is malformed caller input
   *       and is surfaced (stricter than WebIDL {@code ToBoolean} coercion, matching this SDK's
   *       strict-typing stance). The request flags treat {@code false} (and absent/{@code null}) as
   *       "not requested" and ignore it — only {@code true} produces authenticator input; {@code
   *       enforceCredentialProtectionPolicy} treats {@code false} as best-effort (its normal
   *       meaning).
   * </ul>
   *
   * <p><b>Invariant:</b> a throw only becomes a clean {@link ClientError} if it happens in the
   * synchronous phase caught here. The deferred output providers ({@code serializationType -> ...}
   * returned by {@code getOutput}) run later during response serialization, <em>outside</em> this
   * handler, so they MUST NOT throw — any throwing work (parsing/decrypting/validating
   * authenticator output) is done synchronously and yields {@code null} on failure, leaving the
   * provider as pure formatting.
   *
   * <h2>Exception mapping</h2>
   *
   * <ul>
   *   <li><b>{@link ExtensionConfigurationException} — abort.</b> The relying party explicitly
   *       requested a capability that cannot be satisfied, or a spec-defined {@code
   *       NotSupportedError} condition (e.g. {@code credProtect} with {@code
   *       enforceCredentialProtectionPolicy}, {@code largeBlob} {@code support:"required"} on an
   *       unsupported authenticator, or {@code prf} {@code evalByCredential} during registration).
   *       Surfaced as a {@link ClientError} carrying the {@link ClientError.Code} the extension
   *       chose (defaulting to {@link ClientError.Code#CONFIGURATION_UNSUPPORTED}) with the
   *       exception itself as the {@code ClientError} cause. When the authenticator lacks a
   *       required capability the exception is the subtype {@link ExtensionNotSupportedException},
   *       which a caller can test for with {@code instanceof}.
   *   <li><b>{@link IllegalArgumentException} — abort as {@link ClientError.Code#BAD_REQUEST}.</b>
   *       Malformed caller input for a requested extension: a missing required member, a wrong type
   *       on a dictionary/{@code BufferSource} member, an invalid base64url value, or a
   *       spec-defined {@code SyntaxError} (e.g. a {@code prf} {@code evalByCredential} key that
   *       does not match an allowed credential). This is surfaced regardless of whether the
   *       authenticator supports the extension, since several extensions validate their input
   *       before checking support (e.g. {@code largeBlob}, {@code previewSign}). Distinct from the
   *       {@code null} "not applicable" path. Wrapped into an {@link
   *       ExtensionConfigurationException} (original exception preserved as its cause) so the
   *       {@code ClientError} cause is always an {@code ExtensionConfigurationException} for any
   *       extension failure.
   *   <li><b>Anything else — rethrow.</b> Any other unchecked exception (e.g. {@link
   *       NullPointerException}, {@link ClassCastException}, {@link IllegalStateException}) is
   *       treated as a genuine defect and propagated unchanged rather than silently swallowed.
   * </ul>
   */
  private static void handleExtensionFailure(RuntimeException e) throws ClientError {
    if (e instanceof ExtensionConfigurationException) {
      ExtensionConfigurationException configError = (ExtensionConfigurationException) e;
      String message =
          configError.getMessage() != null ? configError.getMessage() : configError.toString();
      throw new ClientError(configError.getCode(), message, configError);
    }
    if (e instanceof IllegalArgumentException) {
      // Malformed caller input for a requested extension (see the class of cases in the Javadoc
      // contract above); surfaced regardless of authenticator support, since several extensions
      // validate input before checking support. Surfaced as BAD_REQUEST rather than silently
      // dropped, which would mask a relying-party bug. Genuine programming defects (other unchecked
      // exceptions) are not masked: they fall through to the final rethrow.
      //
      // Wrapped into an ExtensionConfigurationException carrier so the ClientError cause is always
      // an ExtensionConfigurationException for any extension failure (hard-config or malformed
      // input): a caller can test for "an extension request failed" with a single instanceof rather
      // than guessing from the shared BAD_REQUEST code. The original IllegalArgumentException is
      // preserved as the carrier's cause.
      String message = e.getMessage() != null ? e.getMessage() : e.toString();
      ExtensionConfigurationException carrier =
          new ExtensionConfigurationException(ClientError.Code.BAD_REQUEST, message, e);
      throw new ClientError(ClientError.Code.BAD_REQUEST, message, carrier);
    }
    throw e;
  }

  /**
   * Validate the device-independent client extension inputs of a registration request, without a
   * key.
   *
   * <p>Runs each extension's {@link Extension#validateCreateInputs} and surfaces any failure as the
   * same {@link ClientError} {@link #makeCredential} would throw for it. This lets a caller reject
   * a request that can never succeed <em>before</em> connecting to (or prompting for) an
   * authenticator — matching a browser's synchronous {@code NotSupportedError}/{@code SyntaxError}.
   *
   * <p>This is an optional fast-path: the same checks run inside {@link #makeCredential}, so a
   * caller that skips this still gets identical errors, just later. It only covers request-shape
   * checks; capability checks that need the authenticator's {@code info} (e.g. {@code largeBlob}
   * {@code support:"required"}, {@code credProtect} enforce) are not performed here.
   *
   * <p>Coverage is per-extension: only extensions that override {@link
   * Extension#validateCreateInputs}/{@link Extension#validateGetInputs} participate (currently
   * {@code largeBlob}). An extension whose hard-failures are only raised once the authenticator's
   * support is known (e.g. {@code prf}/{@code hmac-secret}, whose {@code evalByCredential} checks
   * sit behind a support gate in {@link #makeCredential}/{@link #getAssertion}) is intentionally
   * <em>not</em> pre-validated here — doing so would reject a request the device path would accept
   * by ignoring the extension. Such requests still surface their error on the device path.
   *
   * @param options the registration request to validate
   * @param extensions the extensions to check, or {@code null} for the default set
   * @throws ClientError if a requested extension input cannot be satisfied
   */
  public static void validateExtensionInputs(
      PublicKeyCredentialCreationOptions options, @Nullable List<Extension> extensions)
      throws ClientError {
    for (Extension extension : extensions != null ? extensions : defaultExtensions) {
      try {
        extension.validateCreateInputs(options);
      } catch (RuntimeException e) {
        handleExtensionFailure(e);
      }
    }
  }

  /**
   * Validate the device-independent client extension inputs of an authentication request, without a
   * key. The authentication counterpart of {@link #validateExtensionInputs(
   * PublicKeyCredentialCreationOptions, List)}; see it for semantics.
   *
   * @param options the authentication request to validate
   * @param extensions the extensions to check, or {@code null} for the default set
   * @throws ClientError if a requested extension input cannot be satisfied
   */
  public static void validateExtensionInputs(
      PublicKeyCredentialRequestOptions options, @Nullable List<Extension> extensions)
      throws ClientError {
    for (Extension extension : extensions != null ? extensions : defaultExtensions) {
      try {
        extension.validateGetInputs(options);
      } catch (RuntimeException e) {
        handleExtensionFailure(e);
      }
    }
  }

  private int getSafePinRetryCount() {
    try {
      return clientPin.getPinRetries().getCount();
    } catch (IOException | CommandException e) {
      logger.warn("Failed to get PIN retries", e);
      return -1;
    }
  }

  private int getSafeUvRetryCount() {
    try {
      return clientPin.getUvRetries();
    } catch (IOException | CommandException e) {
      logger.warn("Failed to get UV retries", e);
      return -1;
    }
  }

  private static boolean isPublicKeyCredentialTypeSupported(String type) {
    return PUBLIC_KEY.equals(type);
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
     * @return first acceptable credential from the list available on the authenticator or null if
     *     no acceptable credential is present in the list
     */
    @Nullable
    static PublicKeyCredentialDescriptor filterCreds(
        Ctap2Session ctap,
        @Nullable String rpId,
        List<PublicKeyCredentialDescriptor> descriptors,
        String effectiveDomain,
        @Nullable PinUvAuthProtocol pinUvAuthProtocol,
        byte @Nullable [] pinUvAuthToken)
        throws IOException, CommandException, ClientError {
      if (rpId == null) {
        rpId = effectiveDomain;
      } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
        throw new ClientError(
            ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
      }

      Ctap2Session.InfoData info = ctap.getCachedInfo();
      final List<PublicKeyCredentialDescriptor> creds =
          Utils.preprocessCredentialList(
              descriptors, ctap.getCachedInfo().getMaxCredentialIdLength());

      int maxCreds =
          info.getMaxCredentialCountInList() != null ? info.getMaxCredentialCountInList() : 1;

      byte[] clientDataHash = new byte[32];
      Arrays.fill(clientDataHash, (byte) 0x00);

      byte[] pinAuth = null;
      Integer pinUvAuthVersion = null;
      if (pinUvAuthToken != null && pinUvAuthProtocol != null) {
        pinAuth = pinUvAuthProtocol.authenticate(pinUvAuthToken, clientDataHash);
        pinUvAuthVersion = pinUvAuthProtocol.getVersion();
      }

      while (!creds.isEmpty()) {
        logger.trace("Pre-flighting list of {} credentials", creds.size());
        final List<PublicKeyCredentialDescriptor> chunk =
            creds.subList(0, Math.min(maxCreds, creds.size()));
        try {
          List<Ctap2Session.AssertionData> assertions =
              ctap.getAssertions(
                  rpId,
                  clientDataHash,
                  getCredentialList(chunk),
                  null,
                  Collections.singletonMap(OPTION_USER_PRESENCE, false),
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
            logger.trace("No credentials found in chunk");
            chunk.clear();
            continue;
          } else if (ctapError == CtapException.ERR_REQUEST_TOO_LARGE) {
            maxCreds--;
            logger.trace("Chunk request was too large, retrying with {} creds", maxCreds);
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
     * Preprocesses a list of credential descriptors before sending to the authenticator.
     *
     * <p>This method performs the following transformations:
     *
     * <ul>
     *   <li>Filters out unsupported credential types (keeps only "public-key")
     *   <li>Removes credentials exceeding the authenticator's max credential ID length
     *   <li>Strips transport information (not used by CTAP)
     * </ul>
     *
     * @param descriptors The credential descriptors to preprocess
     * @param maxCredIdLength Maximum credential ID length supported by the authenticator, or null
     *     for no limit
     * @return Preprocessed list ready for CTAP operations
     */
    static List<PublicKeyCredentialDescriptor> preprocessCredentialList(
        List<PublicKeyCredentialDescriptor> descriptors, @Nullable Integer maxCredIdLength) {
      if (descriptors.isEmpty()) {
        return descriptors;
      }
      return descriptors.stream()
          .filter(c -> isPublicKeyCredentialTypeSupported(c.getType()))
          .filter(c -> maxCredIdLength == null || c.getId().length <= maxCredIdLength)
          .map(c -> new PublicKeyCredentialDescriptor(c.getType(), c.getId()))
          .collect(Collectors.toList());
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
  }
}

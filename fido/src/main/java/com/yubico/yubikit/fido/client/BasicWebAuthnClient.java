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
  private static final String OPTION_BIO_ENROLL = "bioEnroll";
  private static final String OPTION_RESIDENT_KEY = "rk";
  private static final String OPTION_ALWAYS_UV = "alwaysUv";
  private static final String OPTION_MAKE_CRED_UV_NOT_RQD = "makeCredUvNotRqd";
  private static final String OPTION_EP = "ep";

  private final UserAgentConfiguration userAgentConfiguration = new UserAgentConfiguration();

  private final Ctap2Session ctap;
  private final ClientPin clientPin;

  private final boolean pinSupported;
  private final boolean uvSupported;
  private final boolean bioEnrollSupported;
  private final boolean rkSupported;
  private final boolean tokenSupported;
  private final boolean alwaysUv;
  private final boolean makeCredUvNotRqd;

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

    final InfoOptions options = new InfoOptions(info.getOptions());

    pinSupported = options.supports(OPTION_CLIENT_PIN);
    pinConfigured = options.value(OPTION_CLIENT_PIN);

    uvSupported = options.supports(OPTION_USER_VERIFICATION);
    uvConfigured = options.value(OPTION_USER_VERIFICATION);

    bioEnrollSupported = options.supports(OPTION_BIO_ENROLL);
    bioEnrollConfigured = options.value(OPTION_BIO_ENROLL);

    rkSupported = options.supports(OPTION_RESIDENT_KEY);

    tokenSupported = ClientPin.isTokenSupported(info);
    alwaysUv = options.value(OPTION_ALWAYS_UV);
    makeCredUvNotRqd = options.value(OPTION_MAKE_CRED_UV_NOT_RQD);

    enterpriseAttestationSupported = options.value(OPTION_EP);

    this.clientPin =
        new ClientPin(ctap, getPreferredPinUvAuthProtocol(info.getPinUvAuthProtocols()));
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
  protected Pair<Ctap2Session.CredentialData, ClientExtensionResults> ctapMakeCredential(
      byte[] clientDataHash,
      PublicKeyCredentialCreationOptions options,
      String effectiveDomain,
      @Nullable char[] pin,
      @Nullable Integer enterpriseAttestation,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {

    final MakeCredentialContext context =
        new MakeCredentialContext(
            clientDataHash, options, effectiveDomain, pin, enterpriseAttestation, state);

    while (true) {
      try {
        return context.makeCredential();
      } catch (CtapException e) {
        if (e.getCtapError() == CtapException.ERR_PUAT_REQUIRED
            && context.userVerification.equals(UserVerificationRequirement.DISCOURAGED)) {
          context.userVerification = UserVerificationRequirement.REQUIRED;
          continue;
        }
        throw e;
      }
    }
  }

  /**
   * MakeCredentialContext wraps parameters and functionality for executing makeCredential on
   * authenticator.
   *
   * <p>This class is not part of the public API and may change in future.
   */
  protected class MakeCredentialContext {

    final byte[] clientDataHash;
    final PublicKeyCredentialCreationOptions options;
    final String effectiveDomain;
    final @Nullable char[] pin;
    final @Nullable Integer validatedEnterpriseAttestation;
    final @Nullable CommandState state;

    final Map<String, ?> rp;
    final @Nullable String rpId;
    final AuthenticatorSelectionCriteria selection;

    final int permissions;
    final List<Extension.RegistrationProcessor> registrationProcessors;
    final Map<String, ?> user;
    final List<Map<String, ?>> pubKeyCredParams;

    final SerializationType serializationType = SerializationType.CBOR;

    String userVerification;

    @SuppressWarnings("unchecked")
    protected MakeCredentialContext(
        byte[] clientDataHash,
        PublicKeyCredentialCreationOptions options,
        String effectiveDomain,
        @Nullable char[] pin,
        @Nullable Integer validatedEnterpriseAttestation,
        @Nullable CommandState state)
        throws ClientError {
      this.clientDataHash = clientDataHash;
      this.options = options;
      this.effectiveDomain = effectiveDomain;
      this.pin = pin;
      this.validatedEnterpriseAttestation = validatedEnterpriseAttestation;
      this.state = state;

      rp = options.getRp().toMap(serializationType);
      rpId = options.getRp().getId();
      if (rpId == null) {
        ((Map<String, Object>) rp).put("id", effectiveDomain);
      } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
        throw new ClientError(
            ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
      }

      selection =
          options.getAuthenticatorSelection() != null
              ? options.getAuthenticatorSelection()
              : new AuthenticatorSelectionCriteria(null, null, null);

      // initial userVerification
      userVerification = selection.getUserVerification();

      int makePermissions = ClientPin.PIN_PERMISSION_MC;
      if (!options.getExcludeCredentials().isEmpty()) {
        makePermissions |= ClientPin.PIN_PERMISSION_GA;
      }
      registrationProcessors = new ArrayList<>();
      for (Extension extension : extensions) {
        Extension.RegistrationProcessor processor =
            extension.makeCredential(ctap, options, clientPin.getPinUvAuth());
        if (processor != null) {
          registrationProcessors.add(processor);
          makePermissions |= processor.getPermissions();
        }
      }
      permissions = makePermissions;

      user = options.getUser().toMap(serializationType);

      pubKeyCredParams = new ArrayList<>();
      for (PublicKeyCredentialParameters param : options.getPubKeyCredParams()) {
        if (isPublicKeyCredentialTypeSupported(param.getType())) {
          pubKeyCredParams.add(param.toMap(serializationType));
        }
      }
    }

    protected Pair<Ctap2Session.CredentialData, ClientExtensionResults> makeCredential()
        throws IOException, CommandException, ClientError {
      final AuthParams authParams = getAuthParams(pin, userVerification, permissions, rpId, state);

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

      HashMap<String, Object> authenticatorInputs = new HashMap<>();
      for (Extension.RegistrationProcessor processor : registrationProcessors) {
        authenticatorInputs.putAll(processor.getInput(authParams.pinToken));
      }

      boolean residentKey =
          Objects.equals(selection.getResidentKey(), ResidentKeyRequirement.REQUIRED)
              || (Objects.equals(selection.getResidentKey(), ResidentKeyRequirement.PREFERRED)
                  && rkSupported);

      Map<String, Boolean> ctapOptions = new HashMap<>();
      if (residentKey || authParams.internalUv) {
        if (residentKey) {
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

      byte[] pinUvAuthParam = null;
      Integer pinUvAuthProtocolVersion = null;
      if (!(clientPin.getPinUvAuth() instanceof PinUvAuthDummyProtocol)
          && authParams.pinToken != null) {
        pinUvAuthParam = clientPin.getPinUvAuth().authenticate(authParams.pinToken, clientDataHash);
        pinUvAuthProtocolVersion = clientPin.getPinUvAuth().getVersion();
      }

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
              ctapOptions.isEmpty() ? null : ctapOptions,
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

    final GetAssertionContext context =
        new GetAssertionContext(clientDataHash, options, effectiveDomain, pin, state);

    while (true) {
      try {
        return context.getAssertions();
      } catch (CtapException e) {
        if (e.getCtapError() == CtapException.ERR_PUAT_REQUIRED
            && context.userVerification.equals(UserVerificationRequirement.DISCOURAGED)) {
          context.userVerification = UserVerificationRequirement.REQUIRED;
          continue;
        }
        throw e;
      }
    }
  }

  /**
   * GetAssertionContext wraps parameters and functionality for executing getAssertions on
   * authenticator.
   *
   * <p>This class is not part of the public API and may change in future.
   */
  protected class GetAssertionContext {
    final byte[] clientDataHash;
    final String effectiveDomain;
    final @Nullable char[] pin;
    final @Nullable CommandState state;

    final int permissions;
    final String rpId;
    final @Nullable List<PublicKeyCredentialDescriptor> allowCredentials;
    final List<Extension.AuthenticationProcessor> authenticationProcessors;

    String userVerification;

    protected GetAssertionContext(
        byte[] clientDataHash,
        PublicKeyCredentialRequestOptions options,
        String effectiveDomain,
        @Nullable char[] pin,
        @Nullable CommandState state)
        throws ClientError {
      this.clientDataHash = clientDataHash;
      this.effectiveDomain = effectiveDomain;
      this.pin = pin;
      this.state = state;

      String rpId = options.getRpId();
      if (rpId == null) {
        rpId = effectiveDomain;
      } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
        throw new ClientError(
            ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
      }
      this.rpId = rpId;

      this.allowCredentials = removeUnsupportedCredentials(options.getAllowCredentials());
      this.userVerification = options.getUserVerification();

      int permissions = ClientPin.PIN_PERMISSION_GA;
      this.authenticationProcessors = new ArrayList<>();
      for (Extension extension : extensions) {
        Extension.AuthenticationProcessor processor =
            extension.getAssertion(ctap, options, clientPin.getPinUvAuth());
        if (processor != null) {
          authenticationProcessors.add(processor);
          permissions |= processor.getPermissions();
        }
      }
      this.permissions = permissions;
    }

    protected List<Pair<Ctap2Session.AssertionData, ClientExtensionResults>> getAssertions()
        throws IOException, CommandException, ClientError {

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

      HashMap<String, Object> authenticatorInputs = new HashMap<>();
      for (Extension.AuthenticationProcessor processor : authenticationProcessors) {
        authenticatorInputs.putAll(processor.getInput(selectedCred, authParams.pinToken));
      }

      Map<String, Boolean> ctapOptions =
          authParams.internalUv ? Collections.singletonMap(OPTION_USER_VERIFICATION, true) : null;

      if (hasValidAllowList && selectedCred == null) {
        // We still need to send a dummy value if there was an allowCredentials list but no
        // matches were found.
        selectedCred =
            new PublicKeyCredentialDescriptor(allowCredentials.get(0).getType(), new byte[] {0x00});
      }

      byte[] pinUvAuthParam = null;
      Integer pinUvAuthProtocolVersion = null;
      if (!(clientPin.getPinUvAuth() instanceof PinUvAuthDummyProtocol)
          && authParams.pinToken != null) {
        pinUvAuthParam = clientPin.getPinUvAuth().authenticate(authParams.pinToken, clientDataHash);
        pinUvAuthProtocolVersion = clientPin.getPinUvAuth().getVersion();
      }

      try {
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

      } catch (CtapException exc) {
        if (exc.getCtapError() == CtapException.ERR_PIN_INVALID) {
          throw new PinInvalidClientError(exc, clientPin.getPinRetries().getCount());
        }
        throw ClientError.wrapCtapException(exc);
      }
    }
  }

  protected static class AuthParams {
    @Nullable final byte[] pinToken;
    final boolean internalUv;

    private AuthParams(@Nullable byte[] pinToken, boolean internalUv) {
      this.pinToken = pinToken;
      this.internalUv = internalUv;
    }
  }

  protected AuthParams getAuthParams(
      @Nullable char[] pin,
      String userVerification,
      int permissions,
      @Nullable String rpId,
      @Nullable CommandState state)
      throws ClientError, IOException, CommandException {
    Ctap2Session.InfoData info = ctap.getCachedInfo();
    byte[] pinToken = null;
    boolean internalUv = false;
    if (shouldUseUv(userVerification, permissions, pin)) {
      boolean allowInternalUv =
          (permissions & ~(ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA)) == 0;
      pinToken = getToken(info, pin, permissions, rpId, allowInternalUv, state);
      if (pinToken == null) {
        internalUv = true;
      }
    }
    return new AuthParams(pinToken, internalUv);
  }

  @Nullable
  protected byte[] getToken(
      Ctap2Session.InfoData info,
      @Nullable char[] pin,
      int permissions,
      @Nullable String rpId,
      boolean allowInternalUv,
      @Nullable CommandState state)
      throws IOException, CommandException, ClientError {

    if (uvConfigured) {
      if (tokenSupported) {
        return clientPin.getUvToken(permissions, rpId, state);
      } else if (allowInternalUv) {
        return null;
      }
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

  protected boolean shouldUseUv(String userVerification, int permissions, @Nullable char[] pin)
      throws ClientError {

    boolean mc = (ClientPin.PIN_PERMISSION_MC & permissions) != 0;
    int additionalPermissions =
        permissions & ~(ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA);

    boolean anyUvSupported = uvSupported | pinSupported | bioEnrollSupported;
    boolean anyUvConfigured = uvConfigured | pinConfigured | bioEnrollConfigured;

    if (userVerification.equals(UserVerificationRequirement.REQUIRED)
        || (userVerification.equals(UserVerificationRequirement.PREFERRED) && anyUvSupported)
        || alwaysUv) {
      if (!anyUvConfigured) {
        throw new ClientError(
            ClientError.Code.CONFIGURATION_UNSUPPORTED,
            "User verification not configured/supported");
      }
      return true;
    } else if (mc && anyUvConfigured && !makeCredUvNotRqd) {
      return true;
    } else return anyUvConfigured && additionalPermissions != 0;
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

  private static class InfoOptions {
    final Map<String, ?> options;

    private InfoOptions(Map<String, ?> options) {
      this.options = options;
    }

    boolean supports(String option) {
      return options.containsKey(option);
    }

    boolean value(String option) {
      return Boolean.TRUE.equals(options.get(option));
    }
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
        creds = descriptors;
      }

      int maxCreds =
          info.getMaxCredentialCountInList() != null ? info.getMaxCredentialCountInList() : 1;

      List<List<PublicKeyCredentialDescriptor>> chunks = new ArrayList<>();
      for (int i = 0; i < creds.size(); i += maxCreds) {
        int last = Math.min(i + maxCreds, creds.size());
        chunks.add(creds.subList(i, last));
      }

      byte[] clientDataHash = new byte[32];
      Arrays.fill(clientDataHash, (byte) 0x00);

      byte[] pinAuth = null;
      Integer pinUvAuthVersion = null;
      if (pinUvAuthToken != null && pinUvAuthProtocol != null) {
        pinAuth = pinUvAuthProtocol.authenticate(pinUvAuthToken, clientDataHash);
        pinUvAuthVersion = pinUvAuthProtocol.getVersion();
      }

      for (List<PublicKeyCredentialDescriptor> chunk : chunks) {
        try {
          List<Ctap2Session.AssertionData> assertions =
              ctap.getAssertions(
                  rpId,
                  clientDataHash,
                  getCredentialList(chunk),
                  null,
                  Collections.singletonMap("up", false),
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
          if (ctapException.getCtapError() == CtapException.ERR_NO_CREDENTIALS) {
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

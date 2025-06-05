/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.fido.client.extensions;

import static com.yubico.yubikit.core.internal.codec.Base64.fromUrlSafeString;
import static com.yubico.yubikit.core.internal.codec.Base64.toUrlSafeString;

import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AttestedCredentialData;
import com.yubico.yubikit.fido.webauthn.AuthenticatorData;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.UserVerificationRequirement;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

class SignExtension extends Extension {

  static final String SIGN = "sign";
  static final String ALGORITHMS = "algorithms";
  static final String PH_DATA = "phData";
  static final String KEY_HANDLE_BY_CREDENTIAL = "keyHandleByCredential";
  static final String GENERATE_KEY = "generateKey";
  static final String GENERATED_KEY = "generatedKey";
  static final String SIGNATURE = "signature";
  static final String PUBLIC_KEY = "publicKey";
  static final String KEY_HANDLE = "keyHandle";

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(SignExtension.class);

  public SignExtension() {
    super(SIGN);
  }

  private static class AuthenticationExtensionsSignInputs {
    @Nullable final SignExtension.AuthenticationExtensionsSignGenerateKeyInputs generateKeyInputs;
    @Nullable final SignExtension.AuthenticationExtensionsSignSignInputs signInputs;

    private AuthenticationExtensionsSignInputs(
        @Nullable SignExtension.AuthenticationExtensionsSignGenerateKeyInputs generateKeyInputs,
        @Nullable SignExtension.AuthenticationExtensionsSignSignInputs signInputs) {
      this.generateKeyInputs = generateKeyInputs;
      this.signInputs = signInputs;
    }

    @SuppressWarnings("unchecked")
    @Nullable
    static SignExtension.AuthenticationExtensionsSignInputs fromMap(
        @Nullable Map<String, ?> inputs) {
      if (inputs == null) {
        return null;
      }

      SignExtension.AuthenticationExtensionsSignGenerateKeyInputs signGenerateKeyInputs =
          SignExtension.AuthenticationExtensionsSignGenerateKeyInputs.fromMap(
              (Map<String, Object>) inputs.get(GENERATE_KEY));
      SignExtension.AuthenticationExtensionsSignSignInputs signSignInputs =
          SignExtension.AuthenticationExtensionsSignSignInputs.fromMap(
              (Map<String, Object>) inputs.get(SIGN));

      return new SignExtension.AuthenticationExtensionsSignInputs(
          signGenerateKeyInputs, signSignInputs);
    }

    Map<String, Object> toMap() {
      Map<String, Object> map = new HashMap<>();
      if (generateKeyInputs != null) {
        map.put(GENERATE_KEY, generateKeyInputs.toMap());
      }

      if (signInputs != null) {
        map.put(SIGN, signInputs.toMap());
      }
      return map;
    }
  }

  private static class AuthenticationExtensionsSignSignInputs {
    private final byte[] phData;
    private final Map<String, byte[]> keyHandleByCredential;

    private AuthenticationExtensionsSignSignInputs(
        byte[] phData, Map<String, byte[]> keyHandleByCredential) {
      this.phData = phData;
      this.keyHandleByCredential = keyHandleByCredential;
    }

    @SuppressWarnings("unchecked")
    @Nullable
    static SignExtension.AuthenticationExtensionsSignSignInputs fromMap(
        @Nullable Map<String, Object> map) {
      if (map == null) {
        return null;
      }

      String phData = Objects.requireNonNull((String) map.get(PH_DATA));
      Map<String, String> keyHandleByCredential =
          Objects.requireNonNull((Map<String, String>) map.get(KEY_HANDLE_BY_CREDENTIAL));

      return new SignExtension.AuthenticationExtensionsSignSignInputs(
          fromUrlSafeString(phData),
          keyHandleByCredential.keySet().stream()
              .collect(
                  Collectors.toMap(k -> k, k -> fromUrlSafeString(keyHandleByCredential.get(k)))));
    }

    Map<String, Object> toMap() {
      Map<String, Object> map = new HashMap<>();
      map.put(PH_DATA, toUrlSafeString(phData));
      map.put(
          KEY_HANDLE_BY_CREDENTIAL,
          keyHandleByCredential.keySet().stream()
              .collect(
                  Collectors.toMap(k -> k, k -> toUrlSafeString(keyHandleByCredential.get(k)))));
      return map;
    }
  }

  private static class AuthenticationExtensionsSignGenerateKeyInputs {
    private final List<Integer> algorithms;
    @Nullable private final byte[] phData;

    AuthenticationExtensionsSignGenerateKeyInputs(
        List<Integer> algorithms, @Nullable byte[] phData) {
      this.algorithms = algorithms;
      this.phData = phData;
    }

    @SuppressWarnings("unchecked")
    @Nullable
    static SignExtension.AuthenticationExtensionsSignGenerateKeyInputs fromMap(
        @Nullable Map<String, Object> map) {
      if (map == null) {
        return null;
      }

      List<Integer> algorithms = Objects.requireNonNull((List<Integer>) map.get(ALGORITHMS));
      String phData = (String) map.get(PH_DATA);

      return new SignExtension.AuthenticationExtensionsSignGenerateKeyInputs(
          algorithms, phData != null ? fromUrlSafeString(phData) : null);
    }

    Map<String, Object> toMap() {
      Map<String, Object> map = new HashMap<>();
      map.put(ALGORITHMS, algorithms);
      if (phData != null) {
        map.put(PH_DATA, toUrlSafeString(phData));
      }
      return map;
    }
  }

  private static class AuthenticationExtensionsSignGeneratedKey {
    final byte[] publicKey;
    final byte[] keyHandle;

    private AuthenticationExtensionsSignGeneratedKey(byte[] publicKey, byte[] keyHandle) {
      this.publicKey = publicKey;
      this.keyHandle = keyHandle;
    }

    @SuppressWarnings("unchecked")
    @Nullable
    private static SignExtension.AuthenticationExtensionsSignGeneratedKey fromMap(
        @Nullable Map<String, ?> inputs) {
      if (inputs == null) {
        return null;
      }

      Map<String, Object> generatedKey = (Map<String, Object>) inputs.get(GENERATED_KEY);
      if (generatedKey == null) {
        return null;
      }

      byte[] publicKey = Objects.requireNonNull((byte[]) generatedKey.get("publicKey"));
      byte[] keyHandle = Objects.requireNonNull((byte[]) generatedKey.get("keyHandle"));

      return new SignExtension.AuthenticationExtensionsSignGeneratedKey(publicKey, keyHandle);
    }

    public Map<String, Object> toMap() {
      Map<String, Object> map = new HashMap<>();
      map.put(PUBLIC_KEY, toUrlSafeString(publicKey));
      map.put(KEY_HANDLE, toUrlSafeString(keyHandle));
      return map;
    }
  }

  private static class AuthenticationExtensionsSignOutputs {
    @Nullable final SignExtension.AuthenticationExtensionsSignGeneratedKey generatedKey;
    @Nullable final byte[] signature;

    AuthenticationExtensionsSignOutputs(
        @Nullable Map<Integer, Object> coseKey, @Nullable byte[] signature) {
      byte[] publicKey = null;
      byte[] keyHandle = null;
      if (coseKey != null) {
        publicKey = Cbor.encode(coseKey);

        Map<Integer, Object> keyHandleMap = new HashMap<>();
        for (int key = 1; key <= 3; key++) {
          if (coseKey.containsKey(key)) {
            // TODO only works with ES256, update for ARKG
            keyHandleMap.put(key, key == 1 ? -2 : coseKey.get(key));
          }
        }
        keyHandle = Cbor.encode(keyHandleMap);
      }

      this.generatedKey =
          publicKey != null
              ? new SignExtension.AuthenticationExtensionsSignGeneratedKey(publicKey, keyHandle)
              : null;
      this.signature = signature;
    }

    public Map<String, Object> toMap() {
      Map<String, Object> map = new HashMap<>();
      if (generatedKey != null) {
        map.put(GENERATED_KEY, generatedKey.toMap());
      }
      if (signature != null) {
        map.put(SIGNATURE, toUrlSafeString(signature));
      }
      return map;
    }
  }

  @SuppressWarnings("unchecked")
  @Nullable
  @Override
  public ProcessingResult processInput(CreateInputArguments arguments) {
    Map<String, Object> inputs =
        (Map<String, Object>) arguments.getCreationOptions().getExtensions().get(SIGN);
    if (inputs == null) {
      return null;
    }
    SignExtension.AuthenticationExtensionsSignInputs signInputs =
        SignExtension.AuthenticationExtensionsSignInputs.fromMap(inputs);

    if (signInputs == null || !isSupported(arguments.getCtap())) {
      return null;
    }

    SignExtension.AuthenticationExtensionsSignGenerateKeyInputs generateKeyInputs =
        signInputs.generateKeyInputs;

    if (signInputs.signInputs != null || generateKeyInputs == null) {
      throw new IllegalArgumentException("Invalid inputs");
    }

    Map<Integer, Object> map = new HashMap<>();
    map.put(3, generateKeyInputs.algorithms);
    map.put(4, getCreateFlags(arguments));
    if (generateKeyInputs.phData != null) {
      map.put(0, generateKeyInputs.phData);
    }

    return resultWithData(name, map);
  }

  private int getCreateFlags(CreateInputArguments arguments) {
    PublicKeyCredentialCreationOptions options = arguments.getCreationOptions();
    AuthenticatorSelectionCriteria selection =
        options.getAuthenticatorSelection() != null
            ? options.getAuthenticatorSelection()
            : new AuthenticatorSelectionCriteria(null, null, null);

    return UserVerificationRequirement.REQUIRED.equals(selection.getUserVerification())
        ? 0b101
        : 0b001;
  }

  @SuppressWarnings("unchecked")
  @Nullable
  @Override
  public ProcessingResult processOutput(AttestationObject attestationObject) {

    Map<String, ?> extensions = attestationObject.getAuthenticatorData().getExtensions();
    if (extensions == null) {
      throw new IllegalArgumentException("Missing extensions output");
    }
    Map<Integer, ?> signAuthenticatorOutput = (Map<Integer, ?>) extensions.get(name);
    byte[] signAttestationObject = (byte[]) signAuthenticatorOutput.get(7);
    if (signAttestationObject == null) {
      throw new IllegalArgumentException("Sign attestation missing");
    }
    Map<Integer, ?> signAttestation = (Map<Integer, ?>) Cbor.decode(signAttestationObject);
    if (signAttestation == null) {
      throw new IllegalArgumentException("Sign attestation invalid");
    }

    AuthenticatorData authenticatorData =
        AuthenticatorData.parseFrom(ByteBuffer.wrap((byte[]) signAttestation.get(2)));
    AttestedCredentialData credentialData = authenticatorData.getAttestedCredentialData();

    if (credentialData == null) {
      throw new IllegalArgumentException("Missing CredentialData");
    }

    return resultWithData(
        SIGN,
        new SignExtension.AuthenticationExtensionsSignOutputs(
                (Map<Integer, Object>) credentialData.getCosePublicKey(),
                (byte[]) signAuthenticatorOutput.get(6))
            .toMap());
  }

  @SuppressWarnings("unchecked")
  @Nullable
  @Override
  public ProcessingResult processInput(GetInputArguments arguments) {

    PublicKeyCredentialRequestOptions requestOptions = arguments.getRequestOptions();
    Map<String, Object> inputs = (Map<String, Object>) requestOptions.getExtensions().get(SIGN);

    SignExtension.AuthenticationExtensionsSignInputs signInputs =
        SignExtension.AuthenticationExtensionsSignInputs.fromMap(inputs);

    if (signInputs == null || !isSupported(arguments.getCtap())) {
      return null;
    }

    SignExtension.AuthenticationExtensionsSignSignInputs signSignInputs = signInputs.signInputs;
    if (signSignInputs == null || signInputs.generateKeyInputs != null) {
      throw new IllegalArgumentException("Invalid inputs");
    }

    Map<String, byte[]> byCreds = signSignInputs.keyHandleByCredential;
    List<PublicKeyCredentialDescriptor> allowList = requestOptions.getAllowCredentials();
    if (allowList.isEmpty()) {
      throw new IllegalArgumentException("sign requires allow_list");
    }

    List<String> ids =
        allowList.stream()
            .map(desc -> (String) toUrlSafeString(desc.getId()))
            .collect(Collectors.toList());

    ids.removeAll(byCreds.keySet());
    if (!ids.isEmpty()) {
      throw new IllegalArgumentException("keyHandleByCredential not valid");
    }

    PublicKeyCredentialDescriptor selected = arguments.getSelectedCredential();
    if (selected == null) {
      throw new IllegalArgumentException("Invalid allowList data");
    }

    Map<Integer, Object> output = new HashMap<>();
    byte[] phData = signSignInputs.phData;
    byte[] kh = byCreds.get(toUrlSafeString(selected.getId()));
    output.put(0, phData);
    output.put(5, Collections.singletonList(kh));
    return resultWithData(name, output);
  }

  @SuppressWarnings("unchecked")
  @Nullable
  @Override
  public ProcessingResult processOutput(Ctap2Session.AssertionData assertionData) {
    AuthenticatorData authenticatorData =
        AuthenticatorData.parseFrom(ByteBuffer.wrap(assertionData.getAuthenticatorData()));

    Map<String, ?> extensionResults = authenticatorData.getExtensions();
    if (extensionResults == null) {
      return null;
    }

    Map<Integer, Object> signResults = (Map<Integer, Object>) extensionResults.get(name);
    return resultWithData(
        SIGN,
        new SignExtension.AuthenticationExtensionsSignOutputs(null, (byte[]) signResults.get(6))
            .toMap());
  }
}

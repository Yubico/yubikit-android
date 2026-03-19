/*
 * Copyright (C) 2024-2025 Yubico.
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
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AttestedCredentialData;
import com.yubico.yubikit.fido.webauthn.AuthenticatorData;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.Extensions;
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
import org.jspecify.annotations.Nullable;

public class SignExtension extends Extension {

  static final String SIGN = "previewSign";
  static final String ALGORITHMS = "algorithms";
  static final String KEY_HANDLE = "keyHandle";
  static final String TBS = "tbs";
  static final String ADDITIONAL_ARGS = "additionalArgs";
  static final String SIGN_BY_CREDENTIAL = "signByCredential";
  static final String GENERATE_KEY = "generateKey";
  static final String GENERATED_KEY = "generatedKey";
  static final String SIGNATURE = "signature";
  static final String PUBLIC_KEY = "publicKey";
  static final String ALGORITHM = "algorithm";
  static final String ATTESTATION_OBJECT = "attestationObject";
  static final String FMT = "fmt";
  static final String AUTH_DATA = "authData";
  static final String ATT_STMT = "attStmt";

  public SignExtension() {
    super(SIGN);
  }

  private static class AuthenticationExtensionsSign {
    @Nullable final AuthenticationExtensionsSignGenerateKey generateKey;
    @Nullable final Map<String, AuthenticationExtensionsSignSign> signByCredential;

    private AuthenticationExtensionsSign(
        @Nullable AuthenticationExtensionsSignGenerateKey generateKey,
        @Nullable Map<String, AuthenticationExtensionsSignSign> signByCredential) {
      this.generateKey = generateKey;
      this.signByCredential = signByCredential;
    }

    @SuppressWarnings("unchecked")
    @Nullable
    static AuthenticationExtensionsSign fromMap(@Nullable Map<String, ?> inputs) {
      if (inputs == null) {
        return null;
      }

      AuthenticationExtensionsSignGenerateKey signGenerateKey =
          AuthenticationExtensionsSignGenerateKey.fromMap(
              (Map<String, Object>) inputs.get(GENERATE_KEY));

      Map<String, Map<String, Object>> signByCredentialRaw =
          (Map<String, Map<String, Object>>) inputs.get(SIGN_BY_CREDENTIAL);
      Map<String, AuthenticationExtensionsSignSign> signByCredential = null;
      if (signByCredentialRaw != null) {
        signByCredential = new HashMap<>();
        for (Map.Entry<String, Map<String, Object>> entry : signByCredentialRaw.entrySet()) {
          signByCredential.put(
              entry.getKey(), AuthenticationExtensionsSignSign.fromMap(entry.getValue()));
        }
      }

      return new AuthenticationExtensionsSign(signGenerateKey, signByCredential);
    }
  }

  private static class AuthenticationExtensionsSignSign {
    private final byte[] keyHandle;
    private final byte[] tbs;
    private final byte @Nullable [] additionalArgs;

    private AuthenticationExtensionsSignSign(
        byte[] keyHandle, byte[] tbs, byte @Nullable [] additionalArgs) {
      this.keyHandle = keyHandle;
      this.tbs = tbs;
      this.additionalArgs = additionalArgs;
    }

    static AuthenticationExtensionsSignSign fromMap(Map<String, Object> map) {
      byte[] keyHandle = fromUrlSafeString(Objects.requireNonNull((String) map.get(KEY_HANDLE)));
      byte[] tbs = fromUrlSafeString(Objects.requireNonNull((String) map.get(TBS)));
      String additionalArgsData = (String) map.get(ADDITIONAL_ARGS);
      byte[] additionalArgs =
          additionalArgsData != null ? fromUrlSafeString(additionalArgsData) : null;

      return new AuthenticationExtensionsSignSign(keyHandle, tbs, additionalArgs);
    }
  }

  private static class AuthenticationExtensionsSignGenerateKey {
    private final List<Integer> algorithms;

    AuthenticationExtensionsSignGenerateKey(List<Integer> algorithms) {
      this.algorithms = algorithms;
    }

    @SuppressWarnings("unchecked")
    @Nullable
    static AuthenticationExtensionsSignGenerateKey fromMap(@Nullable Map<String, Object> map) {
      if (map == null) {
        return null;
      }

      List<Integer> algorithms = Objects.requireNonNull((List<Integer>) map.get(ALGORITHMS));

      return new AuthenticationExtensionsSignGenerateKey(algorithms);
    }
  }

  private static class AuthenticationExtensionsSignGeneratedKey {
    final byte[] keyHandle;
    final byte[] publicKey;
    final int algorithm;
    final byte[] attestationObject;

    private AuthenticationExtensionsSignGeneratedKey(
        byte[] keyHandle, byte[] publicKey, int algorithm, byte[] attestationObject) {
      this.keyHandle = keyHandle;
      this.publicKey = publicKey;
      this.algorithm = algorithm;
      this.attestationObject = attestationObject;
    }

    public Map<String, Object> toMap() {
      Map<String, Object> map = new HashMap<>();
      map.put(KEY_HANDLE, toUrlSafeString(keyHandle));
      map.put(PUBLIC_KEY, toUrlSafeString(publicKey));
      map.put(ALGORITHM, algorithm);
      map.put(ATTESTATION_OBJECT, toUrlSafeString(attestationObject));
      return map;
    }
  }

  private static class AuthenticationExtensionsSignOutputs {
    final SignExtension.@Nullable AuthenticationExtensionsSignGeneratedKey generatedKey;
    final byte @Nullable [] signature;

    AuthenticationExtensionsSignOutputs(
        @Nullable AuthenticationExtensionsSignGeneratedKey generatedKey,
        byte @Nullable [] signature) {
      this.generatedKey = generatedKey;
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
  @Override
  @Nullable
  public RegistrationProcessor makeCredential(
      Ctap2Session ctap2,
      PublicKeyCredentialCreationOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {
    Extensions extensions = options.getExtensions();
    if (extensions == null) {
      return null;
    }

    AuthenticationExtensionsSign extSign =
        AuthenticationExtensionsSign.fromMap((Map<String, ?>) extensions.get(SIGN));

    if (extSign == null || !isSupported(ctap2)) {
      return null;
    }

    if (extSign.signByCredential != null) {
      throw new IllegalArgumentException("signByCredential input not allowed");
    }

    if (extSign.generateKey == null) {
      throw new IllegalArgumentException("generateKey input required");
    }

    final RegistrationInput prepareInput =
        pinToken -> {
          Map<Integer, Object> map = new HashMap<>();
          map.put(3, extSign.generateKey.algorithms); // alg
          map.put(4, getCreateFlags(options)); // flags

          return Collections.singletonMap(name, map);
        };

    final RegistrationOutput prepareOutput =
        (attestationObject, pinToken) ->
            serializationType -> {
              AuthenticatorData authData = attestationObject.getAuthenticatorData();
              Map<String, ?> unsignedExtOutputs = attestationObject.getUnsignedExtensionOutputs();
              if (unsignedExtOutputs == null) {
                throw new IllegalArgumentException("Missing unsigned extension outputs");
              }

              Map<Integer, ?> unsignedSignExtData = (Map<Integer, ?>) unsignedExtOutputs.get(name);
              if (unsignedSignExtData == null) {
                throw new IllegalArgumentException("Missing sign unsigned extension outputs");
              }

              Map<Integer, ?> origAttObj =
                  (Map<Integer, ?>) Cbor.decode((byte[]) unsignedSignExtData.get(7)); // att-obj
              if (origAttObj == null) {
                throw new IllegalArgumentException(
                    "Missing sign unsigned extension attestation object");
              }

              AuthenticatorData innerAuthData =
                  AuthenticatorData.parseFrom(ByteBuffer.wrap((byte[]) origAttObj.get(2)));
              AttestedCredentialData attestedCredentialData =
                  innerAuthData.getAttestedCredentialData();
              if (attestedCredentialData == null) {
                throw new IllegalArgumentException("Missing CredentialData");
              }

              byte[] pkBytes = Cbor.encode(attestedCredentialData.getCosePublicKey()).clone();
              byte[] keyHandle = attestedCredentialData.getCredentialId();

              Map<String, ?> authDataExtensions = authData.getExtensions();
              if (authDataExtensions == null) {
                throw new IllegalArgumentException("Missing extensions output");
              }

              Map<Integer, ?> authDataSign = (Map<Integer, ?>) authDataExtensions.get(name);
              if (authDataSign == null) {
                throw new IllegalArgumentException("Missing sign extension output");
              }

              Map<String, Object> newAttObj = new HashMap<>();
              newAttObj.put(FMT, origAttObj.get(1));
              newAttObj.put(AUTH_DATA, origAttObj.get(2));
              newAttObj.put(ATT_STMT, origAttObj.get(3));

              AuthenticationExtensionsSignGeneratedKey generatedKey =
                  new AuthenticationExtensionsSignGeneratedKey(
                      keyHandle,
                      pkBytes,
                      (int) authDataSign.get(3), // alg
                      Cbor.encode(newAttObj));

              return Collections.singletonMap(
                  SIGN,
                  new SignExtension.AuthenticationExtensionsSignOutputs(generatedKey, null)
                      .toMap());
            };

    return new RegistrationProcessor(prepareInput, prepareOutput);
  }

  private int getCreateFlags(PublicKeyCredentialCreationOptions options) {
    AuthenticatorSelectionCriteria selection =
        options.getAuthenticatorSelection() != null
            ? options.getAuthenticatorSelection()
            : new AuthenticatorSelectionCriteria(null, null, null);

    return UserVerificationRequirement.REQUIRED.equals(selection.getUserVerification())
        ? 0b101
        : 0b001;
  }

  @SuppressWarnings("unchecked")
  @Override
  @Nullable
  public AuthenticationProcessor getAssertion(
      Ctap2Session ctap,
      PublicKeyCredentialRequestOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {

    Extensions extensions = options.getExtensions();
    if (extensions == null) {
      return null;
    }
    Map<String, Object> inputs = (Map<String, Object>) extensions.get(SIGN);

    AuthenticationExtensionsSign extSign = AuthenticationExtensionsSign.fromMap(inputs);
    if (extSign == null || !isSupported(ctap)) {
      return null;
    }

    if (extSign.signByCredential == null || extSign.generateKey != null) {
      throw new IllegalArgumentException("Invalid inputs");
    }

    Map<String, AuthenticationExtensionsSignSign> byCreds = extSign.signByCredential;
    List<PublicKeyCredentialDescriptor> allowList = options.getAllowCredentials();
    if (allowList.isEmpty()) {
      throw new IllegalArgumentException("sign requires allow_list");
    }

    List<String> ids =
        allowList.stream().map(desc -> toUrlSafeString(desc.getId())).collect(Collectors.toList());

    ids.removeAll(byCreds.keySet());
    if (!ids.isEmpty()) {
      throw new IllegalArgumentException("signByCredential not valid");
    }

    final AuthenticationInput prepareInput =
        (selected, pinToken) -> {
          if (selected == null) {
            throw new IllegalArgumentException("Invalid allowList data");
          }

          AuthenticationExtensionsSignSign credInputs =
              byCreds.get(toUrlSafeString(selected.getId()));
          Map<Integer, Object> output = new HashMap<>();
          output.put(2, credInputs.keyHandle); // key-handle
          output.put(6, credInputs.tbs); // tbs
          if (credInputs.additionalArgs != null) {
            output.put(7, credInputs.additionalArgs); // additional-args
          }
          return Collections.singletonMap(name, output);
        };

    final AuthenticationOutput prepareOutput =
        (assertionData, pinToken) -> {
          AuthenticatorData authData =
              AuthenticatorData.parseFrom(ByteBuffer.wrap(assertionData.getAuthenticatorData()));

          Map<String, ?> extensionResults = authData.getExtensions();
          if (extensionResults == null) {
            return null;
          }

          Map<Integer, Object> signResults = (Map<Integer, Object>) extensionResults.get(name);
          return serializationType ->
              Collections.singletonMap(
                  SIGN,
                  new SignExtension.AuthenticationExtensionsSignOutputs(
                          null, (byte[]) signResults.get(6)) // sig
                      .toMap());
        };

    return new AuthenticationProcessor(prepareInput, prepareOutput);
  }
}

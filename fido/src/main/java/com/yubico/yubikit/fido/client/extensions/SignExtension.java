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
import javax.annotation.Nullable;

public class SignExtension extends Extension {

  static final String SIGN = "sign";
  static final String ALGORITHMS = "algorithms";
  static final String TBS = "tbs";
  static final String KEY_HANDLE_BY_CREDENTIAL = "keyHandleByCredential";
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
    @Nullable final AuthenticationExtensionsSignSign sign;

    private AuthenticationExtensionsSign(
        @Nullable AuthenticationExtensionsSignGenerateKey generateKey,
        @Nullable AuthenticationExtensionsSignSign sign) {
      this.generateKey = generateKey;
      this.sign = sign;
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
      AuthenticationExtensionsSignSign signSign =
          AuthenticationExtensionsSignSign.fromMap((Map<String, Object>) inputs.get(SIGN));

      return new AuthenticationExtensionsSign(signGenerateKey, signSign);
    }
  }

  private static class AuthenticationExtensionsSignSign {
    private final byte[] tbs;
    private final Map<String, byte[]> keyHandleByCredential;

    private AuthenticationExtensionsSignSign(
        byte[] tbs, Map<String, byte[]> keyHandleByCredential) {
      this.tbs = tbs;
      this.keyHandleByCredential = keyHandleByCredential;
    }

    @SuppressWarnings("unchecked")
    @Nullable
    static AuthenticationExtensionsSignSign fromMap(@Nullable Map<String, Object> map) {
      if (map == null) {
        return null;
      }

      String tbsData = Objects.requireNonNull((String) map.get(TBS));
      Map<String, String> keyHandleByCredential =
          Objects.requireNonNull((Map<String, String>) map.get(KEY_HANDLE_BY_CREDENTIAL));

      return new AuthenticationExtensionsSignSign(
          fromUrlSafeString(tbsData),
          keyHandleByCredential.keySet().stream()
              .collect(
                  Collectors.toMap(k -> k, k -> fromUrlSafeString(keyHandleByCredential.get(k)))));
    }
  }

  private static class AuthenticationExtensionsSignGenerateKey {
    private final List<Integer> algorithms;
    @Nullable private final byte[] tbs;

    AuthenticationExtensionsSignGenerateKey(List<Integer> algorithms, @Nullable byte[] tbs) {
      this.algorithms = algorithms;
      this.tbs = tbs;
    }

    @SuppressWarnings("unchecked")
    @Nullable
    static AuthenticationExtensionsSignGenerateKey fromMap(@Nullable Map<String, Object> map) {
      if (map == null) {
        return null;
      }

      List<Integer> algorithms = Objects.requireNonNull((List<Integer>) map.get(ALGORITHMS));
      String phData = (String) map.get(TBS);

      return new AuthenticationExtensionsSignGenerateKey(
          algorithms, phData != null ? fromUrlSafeString(phData) : null);
    }

    Map<String, Object> toMap() {
      Map<String, Object> map = new HashMap<>();
      map.put(ALGORITHMS, algorithms);
      if (tbs != null) {
        map.put(TBS, toUrlSafeString(tbs));
      }
      return map;
    }
  }

  private static class AuthenticationExtensionsSignGeneratedKey {
    final byte[] publicKey;
    final int algorithm;
    final byte[] attestationObject;

    private AuthenticationExtensionsSignGeneratedKey(
        byte[] publicKey, int algorithm, byte[] attestationObject) {
      this.publicKey = publicKey;
      this.algorithm = algorithm;
      this.attestationObject = attestationObject;
    }

    public Map<String, Object> toMap() {
      Map<String, Object> map = new HashMap<>();
      map.put(PUBLIC_KEY, toUrlSafeString(publicKey));
      map.put(ALGORITHM, algorithm);
      map.put(ATTESTATION_OBJECT, toUrlSafeString(attestationObject));
      return map;
    }
  }

  private static class AuthenticationExtensionsSignOutputs {
    @Nullable final SignExtension.AuthenticationExtensionsSignGeneratedKey generatedKey;
    @Nullable final byte[] signature;

    AuthenticationExtensionsSignOutputs(
        @Nullable AuthenticationExtensionsSignGeneratedKey generatedKey,
        @Nullable byte[] signature) {
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

    if (extSign.sign != null) {
      throw new IllegalArgumentException("sign input not allowed");
    }

    if (extSign.generateKey == null) {
      throw new IllegalArgumentException("generateKey input required");
    }

    final RegistrationInput prepareInput =
        pinToken -> {
          Map<Integer, Object> map = new HashMap<>();
          if (extSign.generateKey.tbs != null) {
            map.put(6, extSign.generateKey.tbs); // tbs
          }
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
                      pkBytes,
                      (int) authDataSign.get(3), // alg
                      Cbor.encode(newAttObj));

              return Collections.singletonMap(
                  SIGN,
                  new SignExtension.AuthenticationExtensionsSignOutputs(
                          generatedKey, (byte[]) authDataSign.get(6)) // sig
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

    if (extSign.sign == null || extSign.generateKey != null) {
      throw new IllegalArgumentException("Invalid inputs");
    }

    Map<String, byte[]> byCreds = extSign.sign.keyHandleByCredential;
    List<PublicKeyCredentialDescriptor> allowList = options.getAllowCredentials();
    if (allowList.isEmpty()) {
      throw new IllegalArgumentException("sign requires allow_list");
    }

    List<String> ids =
        allowList.stream().map(desc -> toUrlSafeString(desc.getId())).collect(Collectors.toList());

    ids.removeAll(byCreds.keySet());
    if (!ids.isEmpty()) {
      throw new IllegalArgumentException("keyHandleByCredential not valid");
    }

    final AuthenticationInput prepareInput =
        (selected, pinToken) -> {
          if (selected == null) {
            throw new IllegalArgumentException("Invalid allowList data");
          }

          byte[] keyRefBytes = byCreds.get(toUrlSafeString(selected.getId()));
          Map<Integer, Object> output = new HashMap<>();
          output.put(6, extSign.sign.tbs); // tbs
          output.put(5, keyRefBytes); // key-ref
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

/*
 * Copyright (C) 2024-2026 Yubico.
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

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AuthenticatorData;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements the Pseudo-random function (prf) and the hmac-secret and hmac-secret-mc CTAP2
 * extensions.
 *
 * <p>The hmac-secret and hmac-secret-mc extensions are not directly available to clients by
 * default, instead the prf extension is used.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#prf-extension">PRF extension</a>
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-hmac-secret-extension">HMAC
 *     secret extension (hmac-secret)</a>
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-hmac-secret-make-cred-extension">HMAC
 *     Secret MakeCredential Extension (hmac-secret-mc)</a>
 */
public class HmacSecretExtension extends Extension {
  static final String PRF = "prf";
  static final String HMAC_GET_SECRET = "hmacGetSecret";
  static final String HMAC_CREATE_SECRET = "hmacCreateSecret";
  static final String FIRST = "first";
  static final String SECOND = "second";
  static final String OUTPUT_1 = "output1";
  static final String OUTPUT_2 = "output2";
  static final String SALT_1 = "salt1";
  static final String SALT_2 = "salt2";
  static final String ENABLED = "enabled";
  static final String RESULTS = "results";
  static final String EVAL_BY_CREDENTIAL = "evalByCredential";
  static final String EVAL = "eval";
  static final byte[] WEBAUTHN_PRF_BYTES = "WebAuthn PRF".getBytes(StandardCharsets.US_ASCII);
  static final String NAME = "hmac-secret";
  static final String NAME_MC = "hmac-secret-mc";

  private final boolean allowHmacSecret;
  private static final Logger logger = LoggerFactory.getLogger(HmacSecretExtension.class);
  private static final int SALT_LEN = 32;

  public HmacSecretExtension() {
    this(false);
  }

  /**
   * @param allowHmacSecret Set to True to allow hmac-secret and hmac-secret-mc, in addition to prf
   */
  public HmacSecretExtension(boolean allowHmacSecret) {
    super(NAME);
    this.allowHmacSecret = allowHmacSecret;
  }

  @Override
  @Nullable
  public RegistrationProcessor makeCredential(
      Ctap2Session ctap2,
      PublicKeyCredentialCreationOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {
    Extensions extensions = options.getExtensions();
    if (extensions == null || !isSupported(ctap2)) {
      return null;
    }

    boolean prf = extensions.has(PRF);
    boolean hmac = false;
    if (allowHmacSecret) {
      Object hmacCreateSecret = extensions.get(HMAC_CREATE_SECRET);
      if (hmacCreateSecret != null && !(hmacCreateSecret instanceof Boolean)) {
        throw new IllegalArgumentException("hmacCreateSecret must be a boolean");
      }
      hmac = Boolean.TRUE.equals(hmacCreateSecret);
    }

    if (!prf && !hmac) {
      return null;
    }

    // get inputs
    Map<String, Object> extensionInputs = new HashMap<>();
    extensionInputs.put(name, true);

    Inputs inputs = Inputs.fromExtensions(extensions);

    // WebAuthn prf client extension processing (registration): evalByCredential is only valid
    // during authentication; its presence here is a NotSupportedError. This is checked
    // unconditionally, independent of hmac-secret-mc support.
    if (inputs != null && inputs.prf != null && inputs.prf.evalByCredential != null) {
      throw new ExtensionConfigurationException(
          "prf evalByCredential is not valid during registration");
    }

    PinUvAuthHelper pinUvAuthHelper = new PinUvAuthHelper(ctap2, pinUvAuthProtocol);

    if (ctap2.getCachedInfo().getExtensions().contains(NAME_MC)
        && pinUvAuthHelper.keyAgreement != null) {
      Salts salts = prepareSalts(null, null, inputs);

      if (salts != null) {
        byte[] saltEnc = pinUvAuthHelper.encrypt(salts.concat());
        byte[] saltAuth = pinUvAuthHelper.authenticate(saltEnc);

        final Map<Integer, @Nullable Object> hmacCreateSecretInput = new HashMap<>();
        hmacCreateSecretInput.put(1, pinUvAuthHelper.keyAgreement.first);
        hmacCreateSecretInput.put(2, saltEnc);
        hmacCreateSecretInput.put(3, saltAuth);
        hmacCreateSecretInput.put(4, pinUvAuthHelper.clientPin.getPinUvAuth().getVersion());
        extensionInputs.put(NAME_MC, hmacCreateSecretInput);
      }
    } // hmac-secret-mc processing

    return new RegistrationProcessor(
        pinToken -> extensionInputs,
        (attestationObject, pinToken) -> {
          // Read and decrypt the authenticator's hmac-secret-mc output here, in the synchronous
          // phase, so the deferred provider returned below does only (non-throwing) formatting and
          // cannot let an exception escape credential.toMap(). Malformed device output (undecodable
          // ciphertext, a short decrypted result, or a wrong type) is omitted, not surfaced.
          try {
            Map<String, ?> extResult =
                attestationObject.getAuthenticatorData().getExtensions() != null
                    ? attestationObject.getAuthenticatorData().getExtensions()
                    : Collections.emptyMap();
            boolean enabled = Boolean.TRUE.equals(extResult.get(name));
            Object mc = extResult.get(NAME_MC);
            byte[] decrypted = pinUvAuthHelper.decrypt(mc instanceof byte[] ? (byte[]) mc : null);
            // CTAP hmac-secret-mc output is exactly one or two 32-byte blocks; any other length is
            // malformed, so the salt results are omitted (the enabled flag is still reported).
            boolean validLength =
                decrypted != null
                    && (decrypted.length == SALT_LEN || decrypted.length == 2 * SALT_LEN);
            byte[] output1 = validLength ? Arrays.copyOfRange(decrypted, 0, SALT_LEN) : null;
            byte[] output2 =
                validLength && decrypted.length == 2 * SALT_LEN
                    ? Arrays.copyOfRange(decrypted, SALT_LEN, 2 * SALT_LEN)
                    : null;
            return serializationType ->
                formatOutputs(serializationType, enabled, output1, output2, prf);
          } catch (RuntimeException e) {
            logger.debug("Ignoring malformed hmac-secret registration output", e);
            return null;
          }
        });
  }

  @Override
  @Nullable
  public AuthenticationProcessor getAssertion(
      Ctap2Session ctap,
      PublicKeyCredentialRequestOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {
    if (!isSupported(ctap)) {
      return null;
    }

    final PinUvAuthHelper pinUvAuthHelper = new PinUvAuthHelper(ctap, pinUvAuthProtocol);
    if (pinUvAuthHelper.keyAgreement == null) {
      return null;
    }

    final Inputs inputs = Inputs.fromExtensions(options.getExtensions());
    if (inputs == null) {
      return null;
    }
    final AuthenticationInput prepareInput =
        (selected, pinToken) -> {
          Salts salts = prepareSalts(options.getAllowCredentials(), selected, inputs);

          if (salts == null) {
            return null;
          }

          byte[] saltEnc = pinUvAuthHelper.encrypt(salts.concat());
          byte[] saltAuth = pinUvAuthHelper.authenticate(saltEnc);

          final Map<Integer, @Nullable Object> hmacGetSecretInput = new HashMap<>();
          hmacGetSecretInput.put(1, pinUvAuthHelper.keyAgreement.first);
          hmacGetSecretInput.put(2, saltEnc);
          hmacGetSecretInput.put(3, saltAuth);
          hmacGetSecretInput.put(4, pinUvAuthHelper.clientPin.getPinUvAuth().getVersion());
          return Collections.singletonMap(NAME, hmacGetSecretInput);
        };

    final AuthenticationOutput prepareOutput =
        (assertionData, pinToken) -> {
          try {
            AuthenticatorData authenticatorData =
                AuthenticatorData.parseFrom(ByteBuffer.wrap(assertionData.getAuthenticatorData()));

            Map<String, ?> extensionOutputs = authenticatorData.getExtensions();
            if (extensionOutputs == null) {
              return null;
            }

            Object value = extensionOutputs.get(name);
            if (!(value instanceof byte[])) {
              return null;
            }

            byte[] decrypted = pinUvAuthHelper.decrypt((byte[]) value);
            // CTAP hmac-secret output is exactly one or two 32-byte blocks. Any other length is
            // malformed authenticator output -> omit the result rather than zero-padding it into a
            // wrong PRF value.
            if (decrypted == null
                || (decrypted.length != SALT_LEN && decrypted.length != 2 * SALT_LEN)) {
              return null;
            }

            byte[] output1 = Arrays.copyOfRange(decrypted, 0, SALT_LEN);
            byte[] output2 =
                decrypted.length == 2 * SALT_LEN
                    ? Arrays.copyOfRange(decrypted, SALT_LEN, 2 * SALT_LEN)
                    : null;

            logger.debug("PRF outputs decrypted successfully");

            if (inputs.prf != null) {
              return serializationType -> {
                Map<String, Object> results = new HashMap<>();
                results.put(
                    FIRST,
                    serializationType == SerializationType.JSON
                        ? toUrlSafeString(output1)
                        : output1);
                if (output2 != null) {
                  results.put(
                      SECOND,
                      serializationType == SerializationType.JSON
                          ? toUrlSafeString(output2)
                          : output2);
                }
                return Collections.singletonMap(PRF, Collections.singletonMap(RESULTS, results));
              };
            } else {
              return serializationType -> {
                Map<String, Object> results = new HashMap<>();
                results.put(
                    OUTPUT_1,
                    serializationType == SerializationType.JSON
                        ? toUrlSafeString(output1)
                        : output1);
                if (output2 != null) {
                  results.put(
                      OUTPUT_2,
                      serializationType == SerializationType.JSON
                          ? toUrlSafeString(output2)
                          : output2);
                }
                return Collections.singletonMap(HMAC_GET_SECRET, results);
              };
            }
          } catch (RuntimeException e) {
            // Authenticator returned malformed hmac-secret output (undecodable authData, wrong
            // type, or a decrypt failure): omit the result rather than failing the assertion or
            // misreporting the authenticator's fault as a relying-party error.
            logger.debug("Ignoring malformed hmac-secret assertion output", e);
            return null;
          }
        };

    return new AuthenticationProcessor(prepareInput, prepareOutput);
  }

  // Package-private (not private) so it can be unit-tested directly: this is a pure function of its
  // inputs (parsing + SHA-256 salt derivation) with no device I/O, unlike the surrounding
  // key-agreement path which requires a real authenticator.
  @SuppressWarnings("unchecked")
  @Nullable Salts prepareSalts(
      @Nullable List<PublicKeyCredentialDescriptor> allowCredentials,
      @Nullable PublicKeyCredentialDescriptor selected,
      Inputs inputs) {

    Salts salts;
    if (inputs.prf != null) {
      Map<String, Object> prfValues = inputs.prf.eval;
      Map<String, Object> evalByCredential = inputs.prf.evalByCredential;

      if (evalByCredential != null && !evalByCredential.isEmpty()) {
        if (allowCredentials == null || allowCredentials.isEmpty()) {
          // WebAuthn (prf client extension processing): evalByCredential non-empty with an empty
          // allowCredentials is a NotSupportedError -> CONFIGURATION_UNSUPPORTED.
          throw new ExtensionConfigurationException("prf evalByCredential requires an allow list");
        }

        Set<String> ids = new HashSet<>();
        for (PublicKeyCredentialDescriptor descriptor : allowCredentials) {
          ids.add(toUrlSafeString(descriptor.getId()));
        }

        if (!ids.containsAll(evalByCredential.keySet())) {
          // WebAuthn (prf): a key not matching an allowCredentials id is a SyntaxError ->
          // BAD_REQUEST.
          throw new IllegalArgumentException("prf evalByCredential contains an unknown credential");
        }

        if (selected != null) {
          String key = toUrlSafeString(selected.getId());
          if (evalByCredential.containsKey(key)) {
            prfValues = asMap(inputs.prf.evalByCredential.get(key), "prf.evalByCredential entry");
          }
        }
      }

      if (prfValues == null) {
        // No evaluation was requested for this credential: nothing to do (not an error).
        return null;
      }

      logger.debug("Processing PRF inputs");

      String firstInput = asString(prfValues.get(FIRST), "prf eval 'first'");
      if (firstInput == null) {
        // Malformed input: a prf eval block must contain "first".
        throw new IllegalArgumentException("prf eval requires 'first'");
      }

      byte[] first = prfSalt(fromUrlSafeString(firstInput));
      // "second" is optional: an absent or null value means no second salt; a wrong-typed value is
      // malformed input (asString throws IllegalArgumentException -> BAD_REQUEST).
      String secondInput = asString(prfValues.get(SECOND), "prf eval 'second'");
      byte[] second = secondInput != null ? prfSalt(fromUrlSafeString(secondInput)) : null;

      salts = new Salts(first, second);
    } else {
      if (inputs.hmac == null) {
        // hmacGetSecret was not requested: nothing to do (not an error).
        return null;
      }

      logger.debug("Processing hmacGetSecret inputs");

      if (inputs.hmac.salt1 == null) {
        // Malformed input: hmacGetSecret must contain salt1.
        throw new IllegalArgumentException("hmacGetSecret requires salt1");
      }

      byte[] salt1 = prfSalt(fromUrlSafeString(inputs.hmac.salt1));
      byte[] salt2 =
          inputs.hmac.salt2 != null ? prfSalt(fromUrlSafeString(inputs.hmac.salt2)) : null;

      salts = new Salts(salt1, salt2);
    }

    logger.debug("Salts prepared");
    if (!(salts.salt1.length == SALT_LEN
        && (salts.salt2.length == 0 || salts.salt2.length == SALT_LEN))) {
      throw new IllegalArgumentException("Invalid salt length");
    }

    return salts;
  }

  private Map<String, Object> formatOutputs(
      SerializationType serializationType,
      @Nullable Boolean enabled,
      byte @Nullable [] output1,
      byte @Nullable [] output2,
      boolean prf) {
    // Pure formatting: callers slice the decrypted bytes into output1/output2 beforehand, so this
    // only selects the wire encoding (raw bytes for CBOR, base64url for JSON) and cannot throw.
    Map<String, @Nullable Object> result = new HashMap<>();
    if (prf) {
      result.put(ENABLED, enabled);
      Map<String, Object> results = new HashMap<>();
      if (output1 != null) {
        results.put(
            FIRST,
            serializationType == SerializationType.JSON ? toUrlSafeString(output1) : output1);
      }
      if (output2 != null && output2.length > 0) {
        results.put(
            SECOND,
            serializationType == SerializationType.JSON ? toUrlSafeString(output2) : output2);
      }
      if (!results.isEmpty()) {
        result.put(RESULTS, results);
      }
      return enabled != null ? Collections.singletonMap(PRF, result) : Collections.emptyMap();

    } else {
      if (output1 != null) {
        result.put(
            OUTPUT_1,
            serializationType == SerializationType.JSON ? toUrlSafeString(output1) : output1);
      }
      if (output2 != null && output2.length > 0) {
        result.put(
            OUTPUT_2,
            serializationType == SerializationType.JSON ? toUrlSafeString(output2) : output2);
      }
      Map<String, Object> hmacSecretResults = new HashMap<>();
      if (enabled != null) {
        hmacSecretResults.put(HMAC_CREATE_SECRET, enabled);
      }
      if (output1 != null) {
        hmacSecretResults.put(HMAC_GET_SECRET, result);
      }
      return hmacSecretResults;
    }
  }

  static class Salts {
    byte[] salt1;
    byte[] salt2;

    Salts(byte[] salt1, byte @Nullable [] salt2) {
      this.salt1 = salt1;
      this.salt2 = salt2 != null ? salt2 : new byte[0];
    }

    byte[] concat() {
      ByteBuffer buffer = ByteBuffer.allocate(salt1.length + salt2.length);
      buffer.put(salt1).put(salt2);
      return buffer.array();
    }
  }

  private byte[] prfSalt(byte[] secret) {
    try {
      return MessageDigest.getInstance("SHA-256")
          .digest(
              ByteBuffer.allocate(13 + secret.length)
                  .put(WEBAUTHN_PRF_BYTES)
                  .put((byte) 0x00)
                  .put(secret)
                  .array());
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 missing", e);
    }
  }

  /**
   * Returns {@code value} as a {@code Map} (a dictionary extension member). Absent values are
   * ignored ({@code null}); a wrong-typed value is malformed structure and is surfaced as an {@link
   * IllegalArgumentException} (mapped to {@code BAD_REQUEST}).
   */
  @SuppressWarnings("unchecked")
  @Nullable
  private static Map<String, Object> asMap(@Nullable Object value, String field) {
    if (value == null) {
      return null;
    }
    if (!(value instanceof Map)) {
      throw new IllegalArgumentException(field + " must be an object");
    }
    return (Map<String, Object>) value;
  }

  /**
   * Returns {@code value} as a {@code String} (a base64url BufferSource member). Absent values are
   * ignored ({@code null}); a wrong-typed value is malformed structure and is surfaced as an {@link
   * IllegalArgumentException} (mapped to {@code BAD_REQUEST}).
   */
  @Nullable
  private static String asString(@Nullable Object value, String field) {
    if (value == null) {
      return null;
    }
    if (!(value instanceof String)) {
      throw new IllegalArgumentException(field + " must be a string");
    }
    return (String) value;
  }

  private static class PrfInputs {
    @Nullable final Map<String, Object> eval;
    @Nullable final Map<String, Object> evalByCredential;

    PrfInputs(@Nullable Map<String, Object> eval, @Nullable Map<String, Object> evalByCredential) {
      this.eval = eval;
      this.evalByCredential = evalByCredential;
    }

    @Nullable
    static PrfInputs fromMap(@Nullable Map<String, Object> map) {
      if (map == null) {
        return null;
      }

      return new PrfInputs(
          asMap(map.get(EVAL), "prf.eval"),
          asMap(map.get(EVAL_BY_CREDENTIAL), "prf.evalByCredential"));
    }
  }

  private static class HmacInputs {
    @Nullable final String salt1;
    @Nullable final String salt2;

    HmacInputs(@Nullable String salt1, @Nullable String salt2) {
      this.salt1 = salt1;
      this.salt2 = salt2;
    }

    @Nullable
    static HmacInputs fromMap(@Nullable Map<String, Object> map) {
      if (map == null) {
        return null;
      }

      return new HmacInputs(
          asString(map.get(SALT_1), "hmacGetSecret.salt1"),
          asString(map.get(SALT_2), "hmacGetSecret.salt2"));
    }
  }

  static class Inputs {
    @Nullable final PrfInputs prf;
    @Nullable final HmacInputs hmac;

    Inputs(@Nullable Map<String, Object> prf, @Nullable Map<String, Object> hmac) {
      this.prf = PrfInputs.fromMap(prf);
      this.hmac = HmacInputs.fromMap(hmac);
    }

    @Nullable
    public static Inputs fromExtensions(@Nullable Extensions extensions) {
      if (extensions == null) {
        return null;
      }

      return new Inputs(
          asMap(extensions.get(PRF), PRF), asMap(extensions.get(HMAC_GET_SECRET), HMAC_GET_SECRET));
    }
  }

  private static class PinUvAuthHelper {
    private final PinUvAuthProtocol pinUvAuthProtocol;
    private final ClientPin clientPin;

    private final @Nullable Pair<Map<Integer, ?>, byte[]> keyAgreement;

    PinUvAuthHelper(Ctap2Session session, PinUvAuthProtocol pinUvAuthProtocol) {
      this.pinUvAuthProtocol = pinUvAuthProtocol;
      this.clientPin = new ClientPin(session, pinUvAuthProtocol);
      Pair<Map<Integer, ?>, byte[]> keyAgreement = null;
      try {
        keyAgreement = clientPin.getSharedSecret();
      } catch (IOException | CommandException e) {
        logger.error("Failed to get shared secret: ", e);
      }
      this.keyAgreement = keyAgreement;
    }

    byte @Nullable [] encrypt(byte[] data) {
      if (keyAgreement == null) {
        return null;
      }
      return clientPin.getPinUvAuth().encrypt(keyAgreement.second, data);
    }

    byte @Nullable [] decrypt(byte @Nullable [] data) {
      if (keyAgreement == null || data == null) {
        return null;
      }
      return pinUvAuthProtocol.decrypt(keyAgreement.second, data);
    }

    byte @Nullable [] authenticate(byte @Nullable [] data) {
      if (keyAgreement == null || data == null) {
        return null;
      }
      return clientPin.getPinUvAuth().authenticate(keyAgreement.second, data);
    }
  }
}

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

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.core.util.StringUtils;
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
import javax.annotation.Nullable;
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
 *     href="https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-extension">HMAC
 *     secret extension (hmac-secret)</a>
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-make-cred-extension">HMAC
 *     Secret MakeCredential Extension (hmac-secret-mc)</a>
 */
public class HmacSecretExtension extends Extension {
  private final boolean allowHmacSecret;
  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(HmacSecretExtension.class);
  private static final int SALT_LEN = 32;

  private static final String PRF = "prf";
  private static final String HMAC_GET_SECRET = "hmacGetSecret";
  private static final String HMAC_CREATE_SECRET = "hmacCreateSecret";
  private static final String FIRST = "first";
  private static final String SECOND = "second";
  private static final String OUTPUT_1 = "output1";
  private static final String OUTPUT_2 = "output2";
  private static final String SALT_1 = "salt1";
  private static final String SALT_2 = "salt2";
  private static final String ENABLED = "enabled";
  private static final String RESULTS = "results";
  private static final String EVAL_BY_CREDENTIAL = "evalByCredential";
  private static final String EVAL = "eval";
  private static final byte[] WEBAUTHN_PRF_BYTES =
      "WebAuthn PRF".getBytes(StandardCharsets.US_ASCII);
  private static final String NAME = "hmac-secret";
  private static final String NAME_MC = "hmac-secret-mc";

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
    boolean hmac = allowHmacSecret && Boolean.TRUE.equals(extensions.get(HMAC_CREATE_SECRET));

    if (!prf && !hmac) {
      return null;
    }

    // get inputs
    Map<String, Object> extensionInputs = new HashMap<>();
    extensionInputs.put(name, true);

    PinUvAuthHelper pinUvAuthHelper = new PinUvAuthHelper(ctap2, pinUvAuthProtocol);

    if (ctap2.getCachedInfo().getExtensions().contains(NAME_MC)
        && pinUvAuthHelper.keyAgreement != null) {
      Inputs inputs = Inputs.fromExtensions(extensions);
      Salts salts = prepareSalts(null, null, inputs);

      if (salts != null) {
        byte[] saltEnc = pinUvAuthHelper.encrypt(salts.concat());
        byte[] saltAuth = pinUvAuthHelper.authenticate(saltEnc);

        final Map<Integer, Object> hmacCreateSecretInput = new HashMap<>();
        hmacCreateSecretInput.put(1, pinUvAuthHelper.keyAgreement.first);
        hmacCreateSecretInput.put(2, saltEnc);
        hmacCreateSecretInput.put(3, saltAuth);
        hmacCreateSecretInput.put(4, pinUvAuthHelper.clientPin.getPinUvAuth().getVersion());
        extensionInputs.put(NAME_MC, hmacCreateSecretInput);
      }
    } // hmac-secret-mc processing

    return new RegistrationProcessor(
        pinToken -> extensionInputs,
        (attestationObject, pinToken) ->
            serializationType -> {
              Map<String, ?> extResult =
                  (attestationObject.getAuthenticatorData().getExtensions() != null)
                      ? attestationObject.getAuthenticatorData().getExtensions()
                      : Collections.emptyMap();
              boolean enabled = Boolean.TRUE.equals(extResult.get(name));
              return formatOutputs(
                  serializationType,
                  enabled,
                  pinUvAuthHelper.decrypt((byte[]) extResult.get(NAME_MC)),
                  prf);
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

          final Map<Integer, Object> hmacGetSecretInput = new HashMap<>();
          hmacGetSecretInput.put(1, pinUvAuthHelper.keyAgreement.first);
          hmacGetSecretInput.put(2, saltEnc);
          hmacGetSecretInput.put(3, saltAuth);
          hmacGetSecretInput.put(4, pinUvAuthHelper.clientPin.getPinUvAuth().getVersion());
          return Collections.singletonMap(NAME, hmacGetSecretInput);
        };

    final AuthenticationOutput prepareOutput =
        (assertionData, pinToken) -> {
          AuthenticatorData authenticatorData =
              AuthenticatorData.parseFrom(ByteBuffer.wrap(assertionData.getAuthenticatorData()));

          Map<String, ?> extensionOutputs = authenticatorData.getExtensions();
          if (extensionOutputs == null) {
            return null;
          }

          byte[] value = (byte[]) extensionOutputs.get(name);
          if (value == null) {
            return null;
          }

          byte[] decrypted = pinUvAuthHelper.decrypt(value);
          if (decrypted == null) {
            return null;
          }

          byte[] output1 = Arrays.copyOf(decrypted, SALT_LEN);
          byte[] output2 =
              decrypted.length > SALT_LEN
                  ? Arrays.copyOfRange(decrypted, SALT_LEN, 2 * SALT_LEN)
                  : new byte[0];

          Logger.debug(
              logger,
              "Decrypted:  {}, o1: {}, o2: {}",
              StringUtils.bytesToHex(decrypted),
              StringUtils.bytesToHex(output1),
              StringUtils.bytesToHex(output2));

          Map<String, Object> results = new HashMap<>();
          if (inputs.prf != null) {
            return serializationType -> {
              results.put(
                  FIRST,
                  serializationType == SerializationType.JSON ? toUrlSafeString(output1) : output1);
              if (output2.length > 0) {
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
              results.put(
                  OUTPUT_1,
                  serializationType == SerializationType.JSON ? toUrlSafeString(output1) : output1);
              if (output2.length > 0) {
                results.put(
                    OUTPUT_2,
                    serializationType == SerializationType.JSON
                        ? toUrlSafeString(output2)
                        : output2);
              }
              return Collections.singletonMap(HMAC_GET_SECRET, results);
            };
          }
        };

    return new AuthenticationProcessor(prepareInput, prepareOutput);
  }

  @SuppressWarnings("unchecked")
  @Nullable
  private Salts prepareSalts(
      @Nullable List<PublicKeyCredentialDescriptor> allowCredentials,
      @Nullable PublicKeyCredentialDescriptor selected,
      Inputs inputs) {

    Salts salts;
    if (inputs.prf != null) {
      Map<String, Object> secrets = inputs.prf.eval;
      Map<String, Object> evalByCredential = inputs.prf.evalByCredential;

      if (evalByCredential != null) {
        if (allowCredentials == null || allowCredentials.isEmpty()) {
          throw new IllegalArgumentException("evalByCredential needs allow list");
        }

        Set<String> ids = new HashSet<>();
        for (PublicKeyCredentialDescriptor descriptor : allowCredentials) {
          ids.add(toUrlSafeString(descriptor.getId()));
        }

        if (!ids.containsAll(evalByCredential.keySet())) {
          throw new IllegalArgumentException("evalByCredentials contains invalid key");
        }

        if (selected != null) {
          String key = toUrlSafeString(selected.getId());
          if (evalByCredential.containsKey(key)) {
            secrets = (Map<String, Object>) inputs.prf.evalByCredential.get(key);
          }
        }
      }

      if (secrets == null) {
        return null;
      }

      Logger.debug(logger, "PRF inputs: {}, {}", secrets.get(FIRST), secrets.get(SECOND));

      String firstInput = (String) secrets.get(FIRST);
      if (firstInput == null) {
        return null;
      }

      byte[] first = prfSalt(fromUrlSafeString(firstInput));
      byte[] second =
          secrets.containsKey(SECOND)
              ? prfSalt(fromUrlSafeString((String) secrets.get(SECOND)))
              : null;

      salts = new Salts(first, second);
    } else {
      if (inputs.hmac == null) {
        return null;
      }

      Logger.debug(
          logger,
          "hmacGetSecret inputs: {}, {}",
          inputs.hmac.salt1 != null ? inputs.hmac.salt1 : "none",
          inputs.hmac.salt2 != null ? inputs.hmac.salt2 : "none");

      if (inputs.hmac.salt1 == null) {
        return null;
      }

      byte[] salt1 = prfSalt(fromUrlSafeString(inputs.hmac.salt1));
      byte[] salt2 =
          inputs.hmac.salt2 != null ? prfSalt(fromUrlSafeString(inputs.hmac.salt2)) : null;

      salts = new Salts(salt1, salt2);
    }

    Logger.debug(
        logger,
        "Salts: {}, {}",
        StringUtils.bytesToHex(salts.salt1),
        StringUtils.bytesToHex(salts.salt2));
    if (!(salts.salt1.length == SALT_LEN
        && (salts.salt2.length == 0 || salts.salt2.length == SALT_LEN))) {
      throw new IllegalArgumentException("Invalid salt length");
    }

    return salts;
  }

  private Map<String, Object> formatOutputs(
      SerializationType serializationType,
      @Nullable Boolean enabled,
      @Nullable byte[] decrypted,
      boolean prf) {
    byte[] output1 = decrypted != null ? Arrays.copyOfRange(decrypted, 0, SALT_LEN) : null;
    byte[] output2 =
        decrypted != null ? Arrays.copyOfRange(decrypted, SALT_LEN, decrypted.length) : null;

    Map<String, Object> result = new HashMap<>();
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

  private static class Salts {
    byte[] salt1;
    byte[] salt2;

    Salts(byte[] salt1, @Nullable byte[] salt2) {
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

  private static class PrfInputs {
    @Nullable final Map<String, Object> eval;
    @Nullable final Map<String, Object> evalByCredential;

    PrfInputs(@Nullable Map<String, Object> eval, @Nullable Map<String, Object> evalByCredential) {
      this.eval = eval;
      this.evalByCredential = evalByCredential;
    }

    @SuppressWarnings("unchecked")
    @Nullable
    static PrfInputs fromMap(@Nullable Map<String, Object> map) {
      if (map == null) {
        return null;
      }

      return new PrfInputs(
          (Map<String, Object>) map.get(EVAL), (Map<String, Object>) map.get(EVAL_BY_CREDENTIAL));
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

      return new HmacInputs((String) map.get(SALT_1), (String) map.get(SALT_2));
    }
  }

  @SuppressWarnings("unchecked")
  private static class Inputs {
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
          (Map<String, Object>) extensions.get(PRF),
          (Map<String, Object>) extensions.get(HMAC_GET_SECRET));
    }
  }

  private static class PinUvAuthHelper {
    private final PinUvAuthProtocol pinUvAuthProtocol;
    private final ClientPin clientPin;

    @Nullable private final Pair<Map<Integer, ?>, byte[]> keyAgreement;

    PinUvAuthHelper(Ctap2Session session, PinUvAuthProtocol pinUvAuthProtocol) {
      this.pinUvAuthProtocol = pinUvAuthProtocol;
      this.clientPin = new ClientPin(session, pinUvAuthProtocol);
      Pair<Map<Integer, ?>, byte[]> keyAgreement = null;
      try {
        keyAgreement = clientPin.getSharedSecret();
      } catch (IOException | CommandException e) {
        Logger.error(logger, "Failed to get shared secret: ", e);
      }
      this.keyAgreement = keyAgreement;
    }

    @Nullable
    byte[] encrypt(byte[] data) {
      if (keyAgreement == null) {
        return null;
      }
      return clientPin.getPinUvAuth().encrypt(keyAgreement.second, data);
    }

    @Nullable
    byte[] decrypt(@Nullable byte[] data) {
      if (keyAgreement == null || data == null) {
        return null;
      }
      return pinUvAuthProtocol.decrypt(keyAgreement.second, data);
    }

    @Nullable
    byte[] authenticate(@Nullable byte[] data) {
      if (keyAgreement == null || data == null) {
        return null;
      }
      return clientPin.getPinUvAuth().authenticate(keyAgreement.second, data);
    }
  }
}

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

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
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
 * Implements the Pseudo-random function (prf) and the hmac-secret CTAP2 extensions.
 *
 * <p>The hmac-secret extension is not directly available to clients by default, instead the prf
 * extension is used.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#prf-extension">PRF extension</a>
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#sctn-hmac-secret-extension">HMAC
 *     secret extension</a>
 */
public class HmacSecretExtension extends Extension {
  private final boolean allowHmacSecret;
  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(HmacSecretExtension.class);
  private static final int SALT_LEN = 32;

  public HmacSecretExtension() {
    this(false);
  }

  /**
   * @param allowHmacSecret Set to True to allow hmac-secret, in addition to prf
   */
  public HmacSecretExtension(boolean allowHmacSecret) {
    super("hmac-secret");
    this.allowHmacSecret = allowHmacSecret;
  }

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
    if (allowHmacSecret && Boolean.TRUE.equals(extensions.get("hmacCreateSecret"))) {
      return new RegistrationProcessor(
          pinToken -> Collections.singletonMap(name, true),
          (attestationObject, pinToken) ->
              serializationType -> registrationOutput(attestationObject, false));
    } else if (extensions.has("prf")) {
      return new RegistrationProcessor(
          pinToken -> Collections.singletonMap(name, true),
          (attestationObject, pinToken) ->
              serializationType -> registrationOutput(attestationObject, true));
    }
    return null;
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

    final ClientPin clientPin = new ClientPin(ctap, pinUvAuthProtocol);
    Pair<Map<Integer, ?>, byte[]> keyAgreement;
    try {
      keyAgreement = clientPin.getSharedSecret();
    } catch (IOException | CommandException e) {
      Logger.error(logger, "Failed to get shared secret: ", e);
      return null;
    }

    final Inputs inputs = Inputs.fromExtensions(options.getExtensions());
    if (inputs == null) {
      return null;
    }
    final AuthenticationInput prepareInput =
        (selected, pinToken) -> {
          Salts salts;
          if (inputs.prf != null) {
            Map<String, Object> secrets = inputs.prf.eval;
            Map<String, Object> evalByCredential = inputs.prf.evalByCredential;

            if (evalByCredential != null) {
              List<PublicKeyCredentialDescriptor> allowCredentials = options.getAllowCredentials();

              if (allowCredentials.isEmpty()) {
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
                  secrets = inputs.evalByCredential(key);
                }
              }
            }

            if (secrets == null) {
              return null;
            }

            Logger.debug(logger, "PRF inputs: {}, {}", secrets.get("first"), secrets.get("second"));

            String firstInput = (String) secrets.get("first");
            if (firstInput == null) {
              return null;
            }

            byte[] first = prfSalt(fromUrlSafeString(firstInput));
            byte[] second =
                secrets.containsKey("second")
                    ? prfSalt(fromUrlSafeString((String) secrets.get("second")))
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

          byte[] saltEnc =
              clientPin
                  .getPinUvAuth()
                  .encrypt(
                      keyAgreement.second,
                      ByteBuffer.allocate(salts.salt1.length + salts.salt2.length)
                          .put(salts.salt1)
                          .put(salts.salt2)
                          .array());

          byte[] saltAuth = clientPin.getPinUvAuth().authenticate(keyAgreement.second, saltEnc);

          final Map<Integer, Object> hmacGetSecretInput = new HashMap<>();
          hmacGetSecretInput.put(1, keyAgreement.first);
          hmacGetSecretInput.put(2, saltEnc);
          hmacGetSecretInput.put(3, saltAuth);
          hmacGetSecretInput.put(4, clientPin.getPinUvAuth().getVersion());
          return Collections.singletonMap(name, hmacGetSecretInput);
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

          byte[] decrypted = clientPin.getPinUvAuth().decrypt(keyAgreement.second, value);

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
                  "first",
                  serializationType == SerializationType.JSON ? toUrlSafeString(output1) : output1);
              if (output2.length > 0) {
                results.put(
                    "second",
                    serializationType == SerializationType.JSON
                        ? toUrlSafeString(output2)
                        : output2);
              }
              return Collections.singletonMap("prf", Collections.singletonMap("results", results));
            };
          } else {
            return serializationType -> {
              results.put(
                  "output1",
                  serializationType == SerializationType.JSON ? toUrlSafeString(output1) : output1);
              if (output2.length > 0) {
                results.put(
                    "output2",
                    serializationType == SerializationType.JSON
                        ? toUrlSafeString(output2)
                        : output2);
              }
              return Collections.singletonMap("hmacGetSecret", results);
            };
          }
        };

    return new AuthenticationProcessor(prepareInput, prepareOutput);
  }

  Map<String, Object> registrationOutput(AttestationObject attestationObject, boolean isPrf) {
    Map<String, ?> extensions = attestationObject.getAuthenticatorData().getExtensions();

    boolean enabled = extensions != null && Boolean.TRUE.equals(extensions.get(name));
    return isPrf
        ? Collections.singletonMap("prf", Collections.singletonMap("enabled", enabled))
        : Collections.singletonMap("hmacCreateSecret", enabled);
  }

  private static class Salts {
    byte[] salt1;
    byte[] salt2;

    Salts(byte[] salt1, @Nullable byte[] salt2) {
      this.salt1 = salt1;
      this.salt2 = salt2 != null ? salt2 : new byte[0];
    }
  }

  private byte[] prfSalt(byte[] secret) {
    try {
      return MessageDigest.getInstance("SHA-256")
          .digest(
              ByteBuffer.allocate(13 + secret.length)
                  .put("WebAuthn PRF".getBytes(StandardCharsets.US_ASCII))
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
          (Map<String, Object>) map.get("eval"), (Map<String, Object>) map.get("evalByCredential"));
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

      return new HmacInputs((String) map.get("salt1"), (String) map.get("salt2"));
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
    Map<String, Object> evalByCredential(String key) {
      if (prf == null || prf.evalByCredential == null) {
        return null;
      }

      return (Map<String, Object>) prf.evalByCredential.get(key);
    }

    @Nullable
    public static Inputs fromExtensions(@Nullable Extensions extensions) {
      if (extensions == null) {
        return null;
      }

      return new Inputs(
          (Map<String, Object>) extensions.get("prf"),
          (Map<String, Object>) extensions.get("hmacGetSecret"));
    }
  }
}

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
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResultProvider;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements the Large Blob storage (largeBlob) WebAuthn extension.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">Large blob
 *     extension</a>
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-largeBlobKey-extension">Large
 *     Blob Key (largeBlobKey)</a>
 */
public class LargeBlobExtension extends Extension {
  static final String LARGE_BLOB_KEY = "largeBlobKey";
  static final String LARGE_BLOB = "largeBlob";
  static final String LARGE_BLOBS = "largeBlobs";
  static final String ACTION_READ = "read";
  static final String ACTION_WRITE = "write";
  static final String WRITTEN = "written";
  static final String SUPPORT = "support";
  static final String SUPPORTED = "supported";
  static final String REQUIRED = "required";
  static final String PREFERRED = "preferred";
  static final String BLOB = "blob";
  static final Logger logger = LoggerFactory.getLogger(LargeBlobExtension.class);

  public LargeBlobExtension() {
    super(LARGE_BLOB_KEY);
  }

  @Override
  protected boolean isSupported(Ctap2Session ctap) {
    return super.isSupported(ctap)
        && Boolean.TRUE.equals(ctap.getCachedInfo().getOptions().get(LARGE_BLOBS));
  }

  @Nullable
  @Override
  public RegistrationProcessor makeCredential(
      Ctap2Session ctap,
      PublicKeyCredentialCreationOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {
    final Inputs inputs = Inputs.fromExtensions(options.getExtensions());
    if (inputs != null) {
      // WebAuthn largeBlob client processing (registration): read/write are authentication-only;
      // their presence here is a NotSupportedError.
      if (inputs.read != null || inputs.write != null) {
        throw new ExtensionConfigurationException(
            "largeBlob read/write is not valid during registration");
      }
      if (REQUIRED.equals(inputs.support) && !isSupported(ctap)) {
        throw new ExtensionConfigurationException(
            "Authenticator does not support large blob storage");
      }
      return new RegistrationProcessor(
          pinToken -> Collections.singletonMap(LARGE_BLOB_KEY, true),
          (attestationObject, pinToken) ->
              serializationType ->
                  Collections.singletonMap(
                      LARGE_BLOB,
                      Collections.singletonMap(
                          SUPPORTED, attestationObject.getLargeBlobKey() != null)));
    }
    return null;
  }

  @Nullable
  @Override
  public AuthenticationProcessor getAssertion(
      Ctap2Session ctap,
      PublicKeyCredentialRequestOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {

    final Inputs inputs = Inputs.fromExtensions(options.getExtensions());
    if (inputs == null) {
      return null;
    }
    // WebAuthn largeBlob client processing (authentication). Each condition below is a
    // NotSupportedError in the spec.
    if (inputs.support != null) {
      throw new ExtensionConfigurationException(
          "largeBlob support is not valid during authentication");
    }
    if (inputs.read != null && inputs.write != null) {
      throw new ExtensionConfigurationException(
          "largeBlob read and write must not both be present");
    }
    if (Boolean.TRUE.equals(inputs.read)) {
      return new AuthenticationProcessor(
          (selected, pinToken) -> Collections.singletonMap(LARGE_BLOB_KEY, true),
          (assertionData, pinToken) -> read(assertionData, ctap));
    } else if (inputs.write != null) {
      if (options.getAllowCredentials().size() != 1) {
        throw new ExtensionConfigurationException(
            "largeBlob write requires exactly one allowed credential");
      }
      return new AuthenticationProcessor(
          (selected, pinToken) -> Collections.singletonMap(LARGE_BLOB_KEY, true),
          (assertionData, pinToken) ->
              write(
                  assertionData,
                  ctap,
                  fromUrlSafeString(inputs.write),
                  pinUvAuthProtocol,
                  pinToken),
          ClientPin.PIN_PERMISSION_LBW);
    }
    return null;
  }

  @Nullable ClientExtensionResultProvider read(
      Ctap2Session.AssertionData assertionData, Ctap2Session ctap) {

    byte[] largeBlobKey = assertionData.getLargeBlobKey();
    if (largeBlobKey == null) {
      return null;
    }

    LargeBlobs largeBlobs;
    try {
      largeBlobs = new LargeBlobs(ctap);
    } catch (IllegalStateException e) {
      // Authenticator returned a largeBlobKey but does not support the large blob array; this is an
      // expected, ignorable condition (no blob to read), not a processing failure. Scope this catch
      // to construction only, so an IllegalStateException from getBlob/serialization is not masked.
      logger.debug("Large blob storage not supported; skipping largeBlob output", e);
      return null;
    }

    try {
      byte[] blob = largeBlobs.getBlob(largeBlobKey);
      return serializationType ->
          Collections.singletonMap(
              LARGE_BLOB,
              blob != null
                  ? Collections.singletonMap(
                      BLOB,
                      serializationType == SerializationType.JSON ? toUrlSafeString(blob) : blob)
                  : Collections.emptyMap());
    } catch (IOException | CommandException e) {
      logger.error("LargeBlob processing failed: ", e);
    }

    return null;
  }

  @Nullable ClientExtensionResultProvider write(
      Ctap2Session.AssertionData assertionData,
      Ctap2Session ctap,
      byte[] bytes,
      PinUvAuthProtocol pinUvAuthProtocol,
      byte @Nullable [] pinToken) {

    byte[] largeBlobKey = assertionData.getLargeBlobKey();
    if (largeBlobKey == null) {
      return null;
    }

    LargeBlobs largeBlobs;
    try {
      largeBlobs = new LargeBlobs(ctap, pinUvAuthProtocol, pinToken);
    } catch (IllegalStateException e) {
      // Authenticator returned a largeBlobKey but does not support the large blob array; this is an
      // expected, ignorable condition (nothing to write), not a processing failure. Scope this
      // catch to construction only, so an IllegalStateException from putBlob is not masked.
      logger.debug("Large blob storage not supported; skipping largeBlob output", e);
      return null;
    }

    try {
      largeBlobs.putBlob(largeBlobKey, bytes);

      return serializationType ->
          Collections.singletonMap(LARGE_BLOB, Collections.singletonMap(WRITTEN, true));

    } catch (IOException | CommandException | GeneralSecurityException e) {
      logger.error("LargeBlob processing failed: ", e);
    }

    return null;
  }

  private static class Inputs {
    @Nullable final Boolean read;
    @Nullable final String write;
    @Nullable final String support;

    private Inputs(@Nullable Boolean read, @Nullable String write, @Nullable String support) {
      this.read = read;
      this.write = write;
      this.support = support;
    }

    @Nullable
    static Inputs fromExtensions(@Nullable Extensions extensions) {
      if (extensions == null) {
        return null;
      }

      Map<String, Object> map = asMap(extensions.get(LARGE_BLOB), LARGE_BLOB);
      if (map == null) {
        return null; // not requested
      }
      String support = asString(map.get(SUPPORT), "largeBlob.support");
      if (support != null && !REQUIRED.equals(support) && !PREFERRED.equals(support)) {
        throw new IllegalArgumentException(
            "largeBlob.support must be \"required\" or \"preferred\"");
      }
      return new Inputs(
          asBoolean(map.get(ACTION_READ), "largeBlob.read"),
          asString(map.get(ACTION_WRITE), "largeBlob.write"),
          support);
    }
  }
}

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
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

/**
 * Implements the Large Blob storage (largeBlob) WebAuthn extension.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">Large blob
 *     extension</a>
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-largeBlobKey-extension">Large
 *     Blob Key (largeBlobKey)</a>
 */
public class LargeBlobExtension extends Extension {
  private static final String LARGE_BLOB_KEY = "largeBlobKey";
  private static final String LARGE_BLOB = "largeBlob";
  private static final String LARGE_BLOBS = "largeBlobs";
  private static final String ACTION_READ = "read";
  private static final String ACTION_WRITE = "write";
  private static final String WRITTEN = "written";
  private static final String SUPPORT = "support";
  private static final String SUPPORTED = "supported";
  private static final String REQUIRED = "required";
  private static final String BLOB = "blob";
  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(LargeBlobExtension.class);

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
      if (inputs.read != null || inputs.write != null) {
        throw new IllegalArgumentException("Invalid set of parameters");
      }
      if (REQUIRED.equals(inputs.support) && !isSupported(ctap)) {
        throw new IllegalArgumentException("Authenticator does not support large blob storage");
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
    if (Boolean.TRUE.equals(inputs.read)) {
      return new AuthenticationProcessor(
          (selected, pinToken) -> Collections.singletonMap(LARGE_BLOB_KEY, true),
          (assertionData, pinToken) -> read(assertionData, ctap));
    } else if (inputs.write != null) {
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

  @Nullable
  ClientExtensionResultProvider read(Ctap2Session.AssertionData assertionData, Ctap2Session ctap) {

    byte[] largeBlobKey = assertionData.getLargeBlobKey();
    if (largeBlobKey == null) {
      return null;
    }

    try {
      LargeBlobs largeBlobs = new LargeBlobs(ctap);
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
      Logger.error(logger, "LargeBlob processing failed: ", e);
    }

    return null;
  }

  @Nullable
  ClientExtensionResultProvider write(
      Ctap2Session.AssertionData assertionData,
      Ctap2Session ctap,
      byte[] bytes,
      PinUvAuthProtocol pinUvAuthProtocol,
      @Nullable byte[] pinToken) {

    byte[] largeBlobKey = assertionData.getLargeBlobKey();
    if (largeBlobKey == null) {
      return null;
    }

    try {
      LargeBlobs largeBlobs = new LargeBlobs(ctap, pinUvAuthProtocol, pinToken);
      largeBlobs.putBlob(largeBlobKey, bytes);

      return serializationType ->
          Collections.singletonMap(LARGE_BLOB, Collections.singletonMap(WRITTEN, true));

    } catch (IOException | CommandException | GeneralSecurityException e) {
      Logger.error(logger, "LargeBlob processing failed: ", e);
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

    @SuppressWarnings("unchecked")
    @Nullable
    static Inputs fromExtensions(@Nullable Extensions extensions) {
      if (extensions == null) {
        return null;
      }

      Map<String, Object> data = (Map<String, Object>) extensions.get(LARGE_BLOB);
      if (data == null) {
        return null;
      }
      return new Inputs(
          (Boolean) data.get(ACTION_READ),
          (String) data.get(ACTION_WRITE),
          (String) data.get(SUPPORT));
    }
  }
}

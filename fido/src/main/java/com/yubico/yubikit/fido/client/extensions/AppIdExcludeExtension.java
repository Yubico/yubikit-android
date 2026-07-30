/*
 * Copyright (C) 2026 Yubico.
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

import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements the appidExclude WebAuthn client extension.
 *
 * <p>This extension enables excluding credentials registered via legacy FIDO U2F using the U2F
 * AppID. This prevents re-registration of U2F credentials when migrating to WebAuthn.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-appid-exclude-extension">FIDO AppID
 *     Exclusion Extension</a>
 */
public class AppIdExcludeExtension extends Extension {
  private static final Logger logger = LoggerFactory.getLogger(AppIdExcludeExtension.class);

  public AppIdExcludeExtension() {
    super("appidExclude");
  }

  @Nullable
  @Override
  public RegistrationProcessor makeCredential(
      Ctap2Session ctap,
      PublicKeyCredentialCreationOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {

    Extensions extensions = options.getExtensions();
    if (extensions == null || !extensions.has(name)) {
      return null;
    }

    Object appIdValue = extensions.get(name);
    if (!(appIdValue instanceof String)) {
      return null; // Invalid input type
    }

    // Per spec, this extension has no output
    return new RegistrationProcessor((RegistrationOutput) null);
  }

  /**
   * Accessor for Ctap2Client to retrieve the appIdExclude value.
   *
   * <p>This is an internal method used by Ctap2Client and is not part of the public API.
   *
   * @param options the creation options
   * @param facetId FacetID of the calling application
   * @param facetVerifier verifier used to authorize the calling FacetID for the AppID
   * @return the appIdExclude URL string, or null if not present
   * @throws ClientError if the extension is malformed or the facet is not authorized
   */
  @Nullable
  public static String getAppIdExclude(
      PublicKeyCredentialCreationOptions options,
      @Nullable String facetId,
      @Nullable AppIdFacetVerifier facetVerifier)
      throws ClientError {
    Extensions extensions = options.getExtensions();
    if (extensions == null || !extensions.has("appidExclude")) {
      return null;
    }

    Object appIdValue = extensions.get("appidExclude");
    if (!(appIdValue instanceof String)) {
      throw new ClientError(
          ClientError.Code.BAD_REQUEST, "appidExclude extension must be a String");
    }

    String appIdExclude = (String) appIdValue;
    if (!AppIdValidation.isValidHttpsAppId(appIdExclude)) {
      throw new ClientError(ClientError.Code.BAD_REQUEST, "appidExclude must be an HTTPS URL");
    }

    // Per WebAuthn L3 (§10.1) the authoritative check is that the caller's FacetID is authorized
    // for the AppID, delegated to the AppIdFacetVerifier. That verifier is where same-site /
    // registrable-domain-suffix logic (honoring the Public Suffix List) belongs; the SDK does not
    // perform a naive appId-vs-rpId host comparison here.
    if (facetId == null || facetVerifier == null) {
      throw new ClientError(
          ClientError.Code.BAD_REQUEST,
          "appidExclude extension requires FacetID and AppIdFacetVerifier configuration");
    }

    try {
      if (!facetVerifier.isAuthorizedFacet(appIdExclude, facetId)) {
        throw new ClientError(
            ClientError.Code.BAD_REQUEST, "calling facet is not authorized for appidExclude");
      }
    } catch (ClientError e) {
      throw e;
    } catch (Exception e) {
      logger.warn("Facet verification failed for appidExclude '{}'", appIdExclude, e);
      throw new ClientError(ClientError.Code.BAD_REQUEST, "appidExclude facet verification failed");
    }

    return appIdExclude;
  }
}

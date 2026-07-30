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
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import java.util.Collections;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements the appid WebAuthn client extension.
 *
 * <p>This extension enables authentication with credentials registered via legacy FIDO U2F using
 * the U2F AppID. This is a client extension that causes the client to retry authentication with the
 * AppID as the RP ID if the initial attempt with the standard RP ID fails.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-appid-extension">FIDO AppID Extension</a>
 */
public class AppIdExtension extends Extension {
  private static final Logger logger = LoggerFactory.getLogger(AppIdExtension.class);

  public AppIdExtension() {
    super("appid");
  }

  @Nullable
  @Override
  public AuthenticationProcessor getAssertion(
      Ctap2Session ctap,
      PublicKeyCredentialRequestOptions options,
      PinUvAuthProtocol pinUvAuthProtocol) {

    Extensions extensions = options.getExtensions();
    if (extensions == null || !extensions.has(name)) {
      return null;
    }

    Object appIdValue = extensions.get(name);
    if (!(appIdValue instanceof String)) {
      return null; // Invalid input type
    }

    // Return processor with output that will be set to false initially
    // (Ctap2Client will override to true if appId was actually used)
    return new AuthenticationProcessor(
        (AuthenticationOutput)
            (assertionData, pinToken) ->
                serializationType -> Collections.singletonMap(name, false));
  }

  /**
   * Accessor for Ctap2Client to retrieve the appId value.
   *
   * <p>This is an internal method used by Ctap2Client and is not part of the public API.
   *
   * @param options the request options
   * @param facetId FacetID of the calling application
   * @param facetVerifier verifier used to authorize the calling FacetID for the AppID
   * @return the appId URL string, or null if not present
   * @throws ClientError if the extension is malformed or the facet is not authorized
   */
  @Nullable
  public static String getAppId(
      PublicKeyCredentialRequestOptions options,
      @Nullable String facetId,
      @Nullable AppIdFacetVerifier facetVerifier)
      throws ClientError {
    Extensions extensions = options.getExtensions();
    if (extensions == null || !extensions.has("appid")) {
      return null;
    }

    Object appIdValue = extensions.get("appid");
    if (!(appIdValue instanceof String)) {
      throw new ClientError(ClientError.Code.BAD_REQUEST, "appid extension must be a String");
    }

    String appId = (String) appIdValue;
    if (!AppIdValidation.isValidHttpsAppId(appId)) {
      throw new ClientError(ClientError.Code.BAD_REQUEST, "appid must be an HTTPS URL");
    }

    // Per WebAuthn L3 (§10.1) the authoritative check is that the caller's FacetID is authorized
    // for the AppID, delegated to the AppIdFacetVerifier. That verifier is where same-site /
    // registrable-domain-suffix logic (honoring the Public Suffix List) belongs; the SDK does not
    // perform a naive appId-vs-rpId host comparison here.
    //
    // The appid extension is best-effort: if the client application has not configured FacetID
    // authorization, skip the extension rather than failing the whole ceremony. The only
    // consequence is that credentials registered via legacy U2F will not be found. (appidExclude,
    // by contrast, fails closed — silently ignoring it would allow re-registering an excluded
    // credential.)
    if (facetId == null || facetVerifier == null) {
      logger.warn(
          "appid extension present but no FacetID/AppIdFacetVerifier is configured; skipping it. "
              + "Credentials registered via legacy U2F will not be usable. Configure "
              + "UserAgentConfiguration.setAppIdFacetId(...) and setAppIdFacetVerifier(...) to "
              + "enable the appid extension.");
      return null;
    }

    try {
      if (!facetVerifier.isAuthorizedFacet(appId, facetId)) {
        throw new ClientError(
            ClientError.Code.BAD_REQUEST, "calling facet is not authorized for appid");
      }
    } catch (ClientError e) {
      throw e;
    } catch (Exception e) {
      logger.warn("Facet verification failed for appid '{}'", appId, e);
      throw new ClientError(ClientError.Code.BAD_REQUEST, "appid facet verification failed");
    }

    return appId;
  }
}

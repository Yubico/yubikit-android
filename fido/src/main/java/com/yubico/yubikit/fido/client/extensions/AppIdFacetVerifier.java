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

/**
 * Verifies that a calling FacetID is authorized for a given legacy U2F AppID.
 *
 * <p>The host application is responsible for supplying FacetID context and implementing trusted
 * facets evaluation according to the FIDO AppID and Facets specification.
 */
@FunctionalInterface
public interface AppIdFacetVerifier {
  /**
   * @param appId AppID URL from the WebAuthn extension input.
   * @param facetId FacetID of the calling application.
   * @return true if the facet is authorized to use the AppID.
   * @throws Exception Implementations may throw if trusted facets cannot be evaluated.
   */
  boolean isAuthorizedFacet(String appId, String facetId) throws Exception;
}

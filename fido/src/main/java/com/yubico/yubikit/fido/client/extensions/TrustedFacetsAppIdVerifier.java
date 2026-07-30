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

import com.squareup.moshi.JsonAdapter;
import com.squareup.moshi.Moshi;
import com.squareup.moshi.Types;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.HttpsURLConnection;
import org.jspecify.annotations.Nullable;

/**
 * Default {@link AppIdFacetVerifier} that implements the FIDO AppID and Facets algorithm.
 *
 * <p>Given a legacy U2F AppID (an HTTPS URL), this verifier fetches the <em>TrustedFacets</em> JSON
 * document published at that URL and checks whether the calling application's FacetID appears in
 * the list of trusted facet {@code ids}. This is the standardized part of the appid/appidExclude
 * ceremony and is identical for every application, so it ships in the SDK rather than being
 * hand-rolled by each integrator.
 *
 * <p>The document is expected to have the shape:
 *
 * <pre>{@code
 * {
 *   "trustedFacets": [
 *     {
 *       "version": { "major": 1, "minor": 0 },
 *       "ids": [
 *         "https://login.example.com",
 *         "android:apk-key-hash:9Vb...gA"
 *       ]
 *     }
 *   ]
 * }
 * }</pre>
 *
 * <p>Matching is an exact string comparison between the caller's FacetID and each published id. Web
 * origin normalization and same-site / registrable-domain-suffix evaluation (which require a Public
 * Suffix List) are intentionally out of scope; integrators that need those semantics should supply
 * their own {@link AppIdFacetVerifier}.
 *
 * <p>Results are cached per AppID for the lifetime of this instance. Instances are thread-safe.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-appid-and-facets-v1.2-ps-20170411.html">FIDO
 *     AppID and Facets</a>
 */
public class TrustedFacetsAppIdVerifier implements AppIdFacetVerifier {

  /**
   * Fetches the raw TrustedFacets document for an AppID. Pluggable so the network layer can be
   * replaced (for example in tests, or to route through an application's own HTTP stack).
   */
  public interface AppIdDocumentFetcher {
    /**
     * @param appIdUrl the HTTPS AppID URL to fetch.
     * @return the response body, or {@code null} if the resource does not exist (HTTP 404).
     * @throws IOException on transport failure.
     */
    @Nullable String fetch(String appIdUrl) throws IOException;
  }

  private static final Type MAP_TYPE =
      Types.newParameterizedType(Map.class, String.class, Object.class);
  private static final JsonAdapter<Map<String, Object>> JSON_ADAPTER =
      new Moshi.Builder().build().adapter(MAP_TYPE);

  private final AppIdDocumentFetcher fetcher;
  private final Map<String, Set<String>> cache = new ConcurrentHashMap<>();

  /** Creates a verifier that fetches AppID documents over HTTPS using the JDK. */
  public TrustedFacetsAppIdVerifier() {
    this(new HttpsDocumentFetcher());
  }

  /**
   * Creates a verifier with a custom document fetcher.
   *
   * @param fetcher the fetcher used to retrieve TrustedFacets documents.
   */
  public TrustedFacetsAppIdVerifier(AppIdDocumentFetcher fetcher) {
    this.fetcher = fetcher;
  }

  @Override
  public boolean isAuthorizedFacet(String appId, String facetId) throws IOException {
    return trustedFacetIds(appId).contains(facetId);
  }

  private Set<String> trustedFacetIds(String appId) throws IOException {
    Set<String> cached = cache.get(appId);
    if (cached != null) {
      return cached;
    }
    String body = fetcher.fetch(appId);
    Set<String> ids = body == null ? Collections.emptySet() : parseTrustedFacetIds(body);
    cache.put(appId, ids);
    return ids;
  }

  /**
   * Parses a TrustedFacets JSON document into the flat set of trusted facet ids across all entries.
   * Unknown fields, malformed entries, and non-string ids are ignored rather than causing a
   * failure, so that a partially malformed document simply yields fewer trusted facets.
   */
  static Set<String> parseTrustedFacetIds(String json) throws IOException {
    Map<String, Object> doc = JSON_ADAPTER.fromJson(json);
    if (doc == null) {
      return Collections.emptySet();
    }
    Object trustedFacets = doc.get("trustedFacets");
    if (!(trustedFacets instanceof List)) {
      return Collections.emptySet();
    }
    Set<String> ids = new HashSet<>();
    for (Object entry : (List<?>) trustedFacets) {
      if (!(entry instanceof Map)) {
        continue;
      }
      Object idList = ((Map<?, ?>) entry).get("ids");
      if (!(idList instanceof List)) {
        continue;
      }
      for (Object id : (List<?>) idList) {
        if (id instanceof String) {
          ids.add((String) id);
        }
      }
    }
    return Collections.unmodifiableSet(ids);
  }

  /** Fetches AppID documents over HTTPS using {@link HttpsURLConnection}. */
  static final class HttpsDocumentFetcher implements AppIdDocumentFetcher {
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS = 10_000;
    private static final int MAX_BODY_BYTES =
        1024 * 1024; // 1 MiB guard against oversized documents

    @Nullable
    @Override
    public String fetch(String appIdUrl) throws IOException {
      URLConnection connection = new URL(appIdUrl).openConnection();
      if (!(connection instanceof HttpsURLConnection)) {
        throw new IOException("AppID must be fetched over HTTPS: " + appIdUrl);
      }
      HttpsURLConnection https = (HttpsURLConnection) connection;
      https.setRequestMethod("GET");
      https.setConnectTimeout(CONNECT_TIMEOUT_MS);
      https.setReadTimeout(READ_TIMEOUT_MS);
      https.setInstanceFollowRedirects(true);
      https.setRequestProperty("Accept", "application/fido.trusted-apps+json, application/json");
      try {
        int status = https.getResponseCode();
        if (status == HttpsURLConnection.HTTP_NOT_FOUND) {
          return null;
        }
        if (status < 200 || status >= 300) {
          throw new IOException("Unexpected HTTP status " + status + " fetching AppID " + appIdUrl);
        }
        try (InputStream in = https.getInputStream()) {
          return readAll(in);
        }
      } finally {
        https.disconnect();
      }
    }

    private static String readAll(InputStream in) throws IOException {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      int read;
      while ((read = in.read(buffer)) != -1) {
        out.write(buffer, 0, read);
        if (out.size() > MAX_BODY_BYTES) {
          throw new IOException("AppID document exceeds maximum allowed size");
        }
      }
      return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }
  }
}

/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.fido.client.clientdata;

import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.client.Utils;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nullable;

/**
 * Internal immutable representation of WebAuthn {@code clientDataJSON}.
 *
 * <p>Provides both the raw JSON bytes and their SHA-256 hash. Used when full {@code clientDataJSON}
 * must be supplied (e.g. for attestation) rather than only its hash.
 *
 * <p>Construction either wraps provided raw bytes or builds deterministic JSON from field inputs:
 *
 * <ul>
 *   <li>Standard fields: type, challenge (base64url), origin, crossOrigin, optional topOrigin.
 *   <li>Extra parameters: filtered to exclude reserved keys and serialized in lexicographic key
 *       order at the top level.
 *   <li>Nested structures: values of type {@code Map} and {@code Iterable} (e.g. {@code List},
 *       {@code Set}) are recursively serialized into JSON (not via {@code toString()}).
 *   <li>Nested {@code Map} keys are emitted in the iteration order of the provided map (not
 *       re-sorted). Use {@code LinkedHashMap} if deterministic ordering is required.
 *   <li>Reserved key filtering applies only to the top-level extras; nested maps are not filtered.
 *   <li>Binary ({@code byte[]}) values at any depth are base64url encoded as JSON strings.
 *   <li>Other object types (non-primitive, non-collection, non-byte[]) are serialized via {@code
 *       String.valueOf(value)} as JSON strings.
 * </ul>
 *
 * <p>Reserved keys ignored in top-level extras: {@code type}, {@code challenge}, {@code origin},
 * {@code crossOrigin}, {@code topOrigin}.
 *
 * <p>This class is package-private; external users interact via {@link ClientDataProvider}
 * factories.
 *
 * @see ClientDataProvider
 */
final class JsonClientData implements ClientDataProvider {
  private static final Set<String> RESERVED =
      Collections.unmodifiableSet(
          new HashSet<>(Arrays.asList("type", "challenge", "origin", "crossOrigin", "topOrigin")));

  private final byte[] raw;
  private final byte[] hash;

  JsonClientData(byte[] raw) {
    this.raw = raw.clone();
    this.hash = Utils.hash(this.raw);
  }

  static JsonClientData createFromFields(
      ClientDataType type,
      byte[] challenge,
      String origin,
      boolean crossOrigin,
      @Nullable String topOrigin,
      @Nullable Map<String, ?> extraParameters) {
    byte[] json =
        buildClientDataJson(
            type.jsonValue(), challenge, origin, crossOrigin, topOrigin, extraParameters);
    return new JsonClientData(json);
  }

  @Override
  public byte[] getHash() {
    return hash.clone();
  }

  @Override
  public byte[] getClientDataJson() {
    return raw.clone();
  }

  @Override
  public boolean hasClientDataJson() {
    return true;
  }

  private static byte[] buildClientDataJson(
      String type,
      byte[] challenge,
      String origin,
      boolean crossOrigin,
      @Nullable String topOrigin,
      @Nullable Map<String, ?> extraParameters) {

    if (topOrigin != null && !crossOrigin) {
      crossOrigin = true; // Enforce spec requirement.
    }

    Map<String, ?> extras = (extraParameters == null) ? null : new LinkedHashMap<>(extraParameters);

    ByteArrayOutputStream out = new ByteArrayOutputStream();

    append(out, "{\"type\":");
    jsonString(out, type);

    append(out, ",\"challenge\":");
    jsonString(out, Base64.toUrlSafeString(challenge));

    append(out, ",\"origin\":");
    jsonString(out, origin);

    append(out, ",\"crossOrigin\":");
    append(out, crossOrigin ? "true" : "false");

    if (topOrigin != null) {
      append(out, ",\"topOrigin\":");
      jsonString(out, topOrigin);
    }

    // Build temporary copy (extras only).
    if (extras == null || extras.isEmpty()) {
      // No extras -> final }
      append(out, "}");
      return out.toByteArray();
    }

    // Filter reserved.
    TreeSet<String> keys = new TreeSet<>(extras.keySet());
    keys.removeIf(RESERVED::contains);

    // If none remain, just close }.
    if (keys.isEmpty()) {
      append(out, "}");
      return out.toByteArray();
    }

    append(out, ",");
    boolean first = true;
    for (String k : keys) {
      if (!first) out.write(',');
      first = false;
      jsonString(out, k);
      out.write(':');
      Object v = extras.get(k);
      if (v == null) {
        append(out, "null");
      } else {
        writeJsonValue(out, v);
      }
    }
    append(out, "}");
    return out.toByteArray();
  }

  private static void append(ByteArrayOutputStream out, String s) {
    byte[] bytes = s.getBytes(StandardCharsets.US_ASCII);
    out.write(bytes, 0, bytes.length);
  }

  private static void writeCodePointUtf8(ByteArrayOutputStream out, int cp) {
    if (cp <= 0x7F) {
      out.write(cp);
    } else if (cp <= 0x7FF) {
      out.write(0xC0 | (cp >>> 6));
      out.write(0x80 | (cp & 0x3F));
    } else if (cp <= 0xFFFF) {
      out.write(0xE0 | (cp >>> 12));
      out.write(0x80 | ((cp >>> 6) & 0x3F));
      out.write(0x80 | (cp & 0x3F));
    } else {
      out.write(0xF0 | (cp >>> 18));
      out.write(0x80 | ((cp >>> 12) & 0x3F));
      out.write(0x80 | ((cp >>> 6) & 0x3F));
      out.write(0x80 | (cp & 0x3F));
    }
  }

  // WARNING: Potential infinite recursion for cyclic Map/Iterable structures; caller must ensure
  // acyclic data.
  private static void writeJsonValue(ByteArrayOutputStream out, Object v) {
    if (v instanceof String) {
      jsonString(out, (String) v);
    } else if (v instanceof Boolean) {
      append(out, ((Boolean) v) ? "true" : "false");
    } else if (v instanceof Number) {
      append(out, v.toString());
    } else if (v instanceof byte[]) {
      // Encode binary as base64url string.
      jsonString(out, Base64.toUrlSafeString((byte[]) v));
    } else if (v instanceof Map) {
      @SuppressWarnings("unchecked")
      Map<String, ?> m = (Map<String, ?>) v;
      ByteArrayOutputStream nested = new ByteArrayOutputStream();
      nested.write('{');
      boolean first = true;
      for (Map.Entry<String, ?> e : m.entrySet()) {
        if (!first) nested.write(',');
        first = false;
        jsonString(nested, e.getKey());
        nested.write(':');
        writeJsonValue(nested, e.getValue());
      }
      nested.write('}');
      out.write(nested.toByteArray(), 0, nested.size());
    } else if (v instanceof Iterable) {
      ByteArrayOutputStream nested = new ByteArrayOutputStream();
      nested.write('[');
      boolean first = true;
      for (Object item : (Iterable<?>) v) {
        if (!first) nested.write(',');
        first = false;
        writeJsonValue(nested, item);
      }
      nested.write(']');
      out.write(nested.toByteArray(), 0, nested.size());
    } else {
      jsonString(out, String.valueOf(v));
    }
  }

  // JSON string (ECMAScript style escaping).
  private static void jsonString(ByteArrayOutputStream out, String s) {
    out.write('"');
    for (int i = 0; i < s.length(); ) {
      int cp = s.codePointAt(i);
      if (cp == '"') {
        append(out, "\\\"");
      } else if (cp == '\\') {
        append(out, "\\\\");
      } else if (cp <= 0x1F) {
        appendUnicodeEscape(out, cp);
      } else {
        writeCodePointUtf8(out, cp);
      }
      i += Character.charCount(cp);
    }
    out.write('"');
  }

  // Shared '\\uXXXX' escape (lowercase hex, Java 8 compatible).
  private static void appendUnicodeEscape(ByteArrayOutputStream out, int v) {
    out.write('\\');
    out.write('u');
    for (int shift = 12; shift >= 0; shift -= 4) {
      int nibble = (v >>> shift) & 0xF;
      out.write(nibble < 10 ? ('0' + nibble) : ('a' + (nibble - 10)));
    }
  }
}

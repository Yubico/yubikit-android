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

package com.yubico.yubikit.fido.client;

import static org.junit.Assert.*;

import com.squareup.moshi.JsonReader;
import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider;
import com.yubico.yubikit.fido.client.clientdata.ClientDataType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import okio.Buffer;
import org.junit.Test;

public class ClientDataProviderTest {
  @Test
  public void testFromClientDataJsonProvidesHashAndDefensiveCopies() {
    String json = "{\"type\":\"x\",\"challenge\":\"y\"}";
    byte[] raw = json.getBytes(StandardCharsets.UTF_8);
    ClientDataProvider p = ClientDataProvider.fromClientDataJson(raw);

    assertTrue(p.hasClientDataJson());
    assertArrayEquals(raw, p.getClientDataJson());
    assertArrayEquals(Utils.hash(raw), p.getHash());

    // Mutate original source array after construction (defensive copy check)
    raw[0] = 'Z';
    assertNotEquals(raw[0], p.getClientDataJson()[0]);

    // Defensive copy (mutate returned arrays)
    byte[] r = p.getClientDataJson();
    byte[] h = p.getHash();
    r[0] = 'Z';
    h[0] ^= (byte) 0xFF;
    assertArrayEquals(Utils.hash(json.getBytes(StandardCharsets.UTF_8)), p.getHash());
    assertEquals('{', p.getClientDataJson()[0]);
  }

  @Test
  public void testExtrasMapMutationAfterCreationDoesNotAffectProvider() {
    byte[] challenge = {1, 2, 3};
    Map<String, Object> extras = new LinkedHashMap<>();
    extras.put("a", 1);
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.CREATE, challenge, "https://ex", false, null, extras);
    String before = new String(p.getClientDataJson(), StandardCharsets.UTF_8);
    // mutate extras
    extras.put("b", 2);
    String after = new String(p.getClientDataJson(), StandardCharsets.UTF_8);
    assertEquals(before, after); // provider unaffected
  }

  @Test
  public void testFromHashProvidesHashOnly() {
    byte[] hash = new byte[32];
    for (int i = 0; i < hash.length; i++) hash[i] = (byte) i;
    ClientDataProvider p = ClientDataProvider.fromHash(hash);

    assertFalse(p.hasClientDataJson());
    assertEquals(0, p.getClientDataJson().length);
    assertArrayEquals(hash, p.getHash());

    // Defensive copy of hash
    byte[] h = p.getHash();
    h[0] ^= (byte) 0xFF;
    assertEquals((byte) 0, p.getHash()[0]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testFromHashRejectsWrongLength() {
    ClientDataProvider.fromHash(new byte[16]);
  }

  @Test
  public void testFromFieldsCreateAndGetBasicStructure() {
    byte[] challenge = {0, 1, 2, 3};
    ClientDataProvider create =
        ClientDataProvider.fromFields(
            ClientDataType.CREATE, challenge, "https://rp.test", false, null, null);

    ClientDataProvider get =
        ClientDataProvider.fromFields(
            ClientDataType.GET, challenge, "https://rp.test", false, null, null);

    assertTrue(create.hasClientDataJson());
    assertTrue(get.hasClientDataJson());
    assertArrayEquals(Utils.hash(create.getClientDataJson()), create.getHash());
    assertArrayEquals(Utils.hash(get.getClientDataJson()), get.getHash());

    Map<String, Object> cm =
        parseJson(new String(create.getClientDataJson(), StandardCharsets.UTF_8));
    Map<String, Object> gm = parseJson(new String(get.getClientDataJson(), StandardCharsets.UTF_8));

    assertEquals("webauthn.create", cm.get("type"));
    assertEquals("webauthn.get", gm.get("type"));

    // Expected challenge
    String expectedChallenge = Base64.toUrlSafeString(challenge);
    assertEquals(expectedChallenge, cm.get("challenge"));
    assertEquals(expectedChallenge, gm.get("challenge"));

    assertEquals("https://rp.test", cm.get("origin"));
    assertEquals("https://rp.test", gm.get("origin"));
    assertEquals(Boolean.FALSE, cm.get("crossOrigin"));
    assertEquals(Boolean.FALSE, gm.get("crossOrigin"));

    assertFalse(cm.containsKey("topOrigin"));
    assertFalse(gm.containsKey("topOrigin"));
  }

  @Test
  public void testCrossOriginAutoEnabledWhenTopOriginProvided() {
    byte[] challenge = {9};
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.GET,
            challenge,
            "https://sub.example",
            false, // pass false: should become true internally
            "https://example",
            null);

    Map<String, Object> m = parseJson(new String(p.getClientDataJson(), StandardCharsets.UTF_8));
    assertEquals(Boolean.TRUE, m.get("crossOrigin"));
    assertEquals("https://example", m.get("topOrigin"));
  }

  @Test
  public void testTopOriginWhenCrossOriginAlreadyTrue() {
    byte[] challenge = {7};
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.GET, challenge, "https://sub.example", true, "https://example", null);
    Map<String, Object> m = parseJson(new String(p.getClientDataJson(), StandardCharsets.UTF_8));
    assertEquals(Boolean.TRUE, m.get("crossOrigin"));
    assertEquals("https://example", m.get("topOrigin"));
  }

  @Test
  public void testExtrasReservedFilteredAndByteArrayEncoding() {
    byte[] challenge = {5, 6};
    byte[] binaryExtra = {10, 11, 12};
    Map<String, Object> extras = new LinkedHashMap<>();
    extras.put("type", "override");
    extras.put("origin", "override");
    extras.put("aKey", 123);
    extras.put("zKey", "value");
    extras.put("mid", binaryExtra);
    extras.put("crossOrigin", true);
    extras.put("challenge", "override");
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.CREATE, challenge, "https://x", true, null, extras);
    Map<String, Object> m = parseJson(new String(p.getClientDataJson(), StandardCharsets.UTF_8));
    assertEquals("webauthn.create", m.get("type"));
    assertEquals("https://x", m.get("origin"));
    assertEquals(Base64.toUrlSafeString(challenge), m.get("challenge"));
    assertEquals(Boolean.TRUE, m.get("crossOrigin"));
    assertEquals(123, m.get("aKey"));
    assertEquals("value", m.get("zKey"));
    assertEquals(Base64.toUrlSafeString(binaryExtra), m.get("mid"));
  }

  @Test
  public void testNullExtraValueSerializedAsNull() {
    byte[] challenge = {1};
    Map<String, Object> extras = new LinkedHashMap<>();
    extras.put("nullable", null);
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.CREATE, challenge, "https://x", false, null, extras);
    String json = new String(p.getClientDataJson(), StandardCharsets.UTF_8);
    assertTrue(json.contains("\"nullable\":null"));
  }

  @Test
  public void testExtraKeyOrderingIsLexicographic() {
    byte[] challenge = {2};
    Map<String, Object> extras = new LinkedHashMap<>();
    extras.put("zzz", 1);
    extras.put("aaa", 2);
    extras.put("mmm", 3);
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.CREATE, challenge, "https://x", false, null, extras);
    String json = new String(p.getClientDataJson(), StandardCharsets.UTF_8);
    int idxA = json.indexOf("\"aaa\"");
    int idxM = json.indexOf("\"mmm\"");
    int idxZ = json.indexOf("\"zzz\"");
    assertTrue(idxA < idxM && idxM < idxZ);
  }

  @Test
  public void testUnicodeEscapingInOrigin() {
    byte[] challenge = {1};
    String originWithControl = "https://ex\n.com"; // \n should be escaped
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.GET, challenge, originWithControl, false, null, null);
    String json = new String(p.getClientDataJson(), StandardCharsets.UTF_8);
    assertTrue(json.contains("\"origin\":\"https://ex\\u000a.com\""));
  }

  @Test
  public void testQuoteAndBackslashEscapingInExtra() {
    byte[] challenge = {3};
    Map<String, Object> extras = new LinkedHashMap<>();
    String original = "He said \"Hi\\Bye\"";
    extras.put("escaped", original);
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.CREATE, challenge, "https://x", false, null, extras);
    String json = new String(p.getClientDataJson(), StandardCharsets.UTF_8);
    String expectedEscaped = "He said \\\"Hi\\\\Bye\\\""; // JSON escaped form
    assertTrue(json.contains("\"escaped\":\"" + expectedEscaped + "\""));
  }

  @Test
  public void testControlCharsEscapedInExtra() {
    byte[] challenge = {4};
    Map<String, Object> extras = new LinkedHashMap<>();
    extras.put("ctrl", "A\u0001B\tC");
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.CREATE, challenge, "https://x", false, null, extras);
    String json = new String(p.getClientDataJson(), StandardCharsets.UTF_8);
    assertTrue(json.contains("\"ctrl\":\"A\\u0001B\\u0009C\""));
  }

  @Test
  public void testEmptyBinaryExtra() {
    byte[] challenge = {5};
    Map<String, Object> extras = new LinkedHashMap<>();
    extras.put("emptyBin", new byte[0]);
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.CREATE, challenge, "https://x", false, null, extras);
    String json = new String(p.getClientDataJson(), StandardCharsets.UTF_8);
    assertTrue(json.contains("\"emptyBin\":\"\"")); // empty base64url string
  }

  @Test
  public void testLargeChallengeBase64UrlNoPadding() {
    byte[] challenge = new byte[64];
    for (int i = 0; i < challenge.length; i++) challenge[i] = (byte) i;
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.CREATE, challenge, "https://x", false, null, null);
    String json = new String(p.getClientDataJson(), StandardCharsets.UTF_8);
    String b64 = Base64.toUrlSafeString(challenge);
    assertTrue(json.contains("\"challenge\":\"" + b64 + "\""));
    assertFalse(b64.contains("="));
  }

  @Test
  public void testCustomClientDataType() {
    byte[] challenge = {8};
    ClientDataType custom = ClientDataType.of("future.type");
    ClientDataProvider p =
        ClientDataProvider.fromFields(custom, challenge, "https://x", false, null, null);
    Map<String, Object> m = parseJson(new String(p.getClientDataJson(), StandardCharsets.UTF_8));
    assertEquals("future.type", m.get("type"));
  }

  @Test
  public void testNestedStructuresAndNestedReservedKey() {
    byte[] challenge = {9};
    Map<String, Object> nested = new LinkedHashMap<>();
    nested.put("type", "innerType");
    nested.put("value", 42);
    nested.put("bin", new byte[] {1, 2});
    List<Object> list = new ArrayList<>();
    list.add("str");
    list.add(new byte[] {3, 4});
    list.add(nested);
    Map<String, Object> extras = new LinkedHashMap<>();
    extras.put("nested", nested);
    extras.put("list", list);
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.CREATE, challenge, "https://x", false, null, extras);
    String json = new String(p.getClientDataJson(), StandardCharsets.UTF_8);
    assertTrue(json.contains("\"nested\""));
    assertTrue(json.contains("\"type\":\"innerType\""));
    assertTrue(json.contains("\"list\""));
    assertTrue(json.contains(Base64.toUrlSafeString(new byte[] {1, 2})));
    assertTrue(json.contains(Base64.toUrlSafeString(new byte[] {3, 4})));
  }

  @Test
  public void testNoExtrasNoTrailingComma() {
    ClientDataProvider p =
        ClientDataProvider.fromFields(
            ClientDataType.CREATE,
            new byte[] {1, 2},
            "https://x",
            false,
            null,
            new LinkedHashMap<>()); // empty extras map

    String json = new String(p.getClientDataJson(), StandardCharsets.UTF_8);
    assertTrue(json.endsWith("}"));
    // Ensure no ",}" sequence
    assertFalse(json.contains(",}"));
  }

  // json helpers
  @SuppressWarnings("unchecked")
  private static Map<String, Object> parseJson(String json) {
    Buffer buffer = new Buffer().write(json.getBytes(StandardCharsets.UTF_8));
    try (JsonReader reader = JsonReader.of(buffer)) {
      Object root = readValue(reader);
      if (!(root instanceof Map)) {
        throw new AssertionError("Root JSON value is not an object");
      }
      return (Map<String, Object>) root;
    } catch (IOException e) {
      throw new AssertionError("Failed to parse JSON", e);
    }
  }

  private static Object readValue(JsonReader reader) throws IOException {
    /* based on SignExtensionTests.JsonUtils.readValue */
    switch (reader.peek()) {
      case BEGIN_OBJECT:
        return readObject(reader);
      case BEGIN_ARRAY:
        return readArray(reader);
      case STRING:
        return reader.nextString();
      case NUMBER:
        String num = reader.nextString();
        try {
          return Integer.parseInt(num);
        } catch (NumberFormatException ignore) {
        }
        try {
          return Long.parseLong(num);
        } catch (NumberFormatException ignore) {
        }
        try {
          return Double.parseDouble(num);
        } catch (NumberFormatException ignore) {
        }
        return num;
      case BOOLEAN:
        return reader.nextBoolean();
      case NULL:
        return reader.nextNull();
      default:
        return null;
    }
  }

  private static Map<String, Object> readObject(JsonReader reader) throws IOException {
    Map<String, Object> map = new LinkedHashMap<>();
    reader.beginObject();
    while (reader.hasNext()) {
      if (reader.peek() == JsonReader.Token.NAME) {
        String name = reader.nextName();
        map.put(name, readValue(reader));
      }
    }
    reader.endObject();
    return map;
  }

  private static List<Object> readArray(JsonReader reader) throws IOException {
    List<Object> list = new ArrayList<>();
    reader.beginArray();
    while (reader.hasNext()) {
      list.add(readValue(reader));
    }
    reader.endArray();
    return list;
  }
}

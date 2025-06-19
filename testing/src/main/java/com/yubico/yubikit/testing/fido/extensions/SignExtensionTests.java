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

package com.yubico.yubikit.testing.fido.extensions;

import com.squareup.moshi.JsonReader;
import com.yubico.yubikit.fido.client.extensions.Extension;
import com.yubico.yubikit.fido.client.extensions.SignExtension;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import okio.Buffer;
import org.junit.Assert;
import org.junit.Assume;

public class SignExtensionTests {

  private static final String SIGN_EXT = "sign";

  private static final List<Extension> extensions = Collections.singletonList(new SignExtension());

  public static void testWithDiscoverableCredential(FidoTestState state) throws Throwable {
    SignExtensionTests extTests = new SignExtensionTests();
    extTests.runTest(state, true);
  }

  public static void testWithNonDiscoverableCredential(FidoTestState state) throws Throwable {
    SignExtensionTests extTests = new SignExtensionTests();
    extTests.runTest(state, false);
  }

  // this test is active only on devices without sign extension
  public static void testNoExtensionSupport(FidoTestState state) throws Throwable {
    SignExtensionTests extTests = new SignExtensionTests();
    extTests.runNoSupportTest(state);
  }

  private SignExtensionTests() {}

  @SuppressWarnings("unchecked")
  private void runTest(FidoTestState state, boolean residentKey) throws Throwable {
    {
      // no output when no input
      state.withCtap2(
          session -> {
            Assume.assumeTrue(session.getCachedInfo().getExtensions().contains(SIGN_EXT));
            PublicKeyCredential cred =
                new ClientHelper(session, extensions)
                    .makeCredential(new CreationOptionsBuilder().residentKey(residentKey).build());
            Assert.assertNull(getSignResult(cred));
            if (residentKey) {
              new ClientHelper(session, extensions).deleteCredentials(cred);
            }
          });

      // create credential
      state.withCtap2(
          session -> {
            PublicKeyCredential cred =
                new ClientHelper(session, extensions)
                    .makeCredential(
                        new CreationOptionsBuilder()
                            .residentKey(residentKey)
                            .extensions(
                                JsonUtils.fromJson(
                                    "{\"sign\": {"
                                        + "    \"generateKey\": {"
                                        + "      \"algorithms\": ["
                                        + "          -65600,"
                                        + "          -65539,"
                                        + "          -9,"
                                        + "          -7"
                                        + "      ]"
                                        + "    }"
                                        + "  }}"))
                            .build());

            Map<String, Object> signCreateResult = getSignResult(cred);
            Assert.assertNotNull(signCreateResult);
            Assert.assertFalse(signCreateResult.containsKey("signature"));
            Map<String, Object> generatedKey =
                (Map<String, Object>) signCreateResult.get("generatedKey");
            Assert.assertNotNull(generatedKey);
            Assert.assertTrue(generatedKey.containsKey("publicKey"));
            Assert.assertTrue(generatedKey.containsKey("algorithm"));
            Assert.assertTrue(generatedKey.containsKey("attestationObject"));

            if (residentKey) {
              new ClientHelper(session, extensions).deleteCredentials(cred);
            }
          });
    }
  }

  private void runNoSupportTest(FidoTestState state) throws Throwable {
    state.withCtap2(
        session -> {
          Assume.assumeFalse(session.getCachedInfo().getExtensions().contains(SIGN_EXT));
          PublicKeyCredential cred =
              new ClientHelper(session, extensions)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .extensions(Collections.singletonMap(SIGN_EXT, Collections.emptyMap()))
                          .build());

          Assert.assertNull(getSignResult(cred));
        });
  }

  @SuppressWarnings("unchecked")
  @Nullable
  private Map<String, Object> getSignResult(PublicKeyCredential credential) {
    ClientExtensionResults results = credential.getClientExtensionResults();
    Assert.assertNotNull(results);
    Map<String, Object> resultsMap = results.toMap(SerializationType.JSON);
    return (Map<String, Object>) resultsMap.get(SIGN_EXT);
  }

  static class JsonUtils {

    @Nullable
    public static Map<String, Object> fromJson(@Nullable String json) throws IOException {
      if (json == null) {
        return null;
      }

      Buffer b = new Buffer();
      b.write(json.getBytes(StandardCharsets.UTF_8));

      try (JsonReader jsonReader = JsonReader.of(b)) {
        return readObject(jsonReader);
      }
    }

    @Nullable
    private static Object readValue(JsonReader reader) throws IOException {
      switch (reader.peek()) {
        case BEGIN_ARRAY:
          return readArray(reader);
        case BEGIN_OBJECT:
          return readObject(reader);
        case STRING:
          return reader.nextString();
        case NUMBER:
          String str = reader.nextString();
          try {
            return Integer.parseInt(str);
          } catch (NumberFormatException intParseException) {
            try {
              return Long.parseLong(str);
            } catch (NumberFormatException longParseException) {
              try {
                return Double.parseDouble(str);
              } catch (NumberFormatException ignoredException) {

              }
            }
          }
          return str;
        case BOOLEAN:
          return reader.nextBoolean();
        case NULL:
          return reader.nextNull();
        default:
          return null;
      }
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

    private static Map<String, Object> readObject(JsonReader reader) throws IOException {
      Map<String, Object> map = new HashMap<>();
      reader.beginObject();
      while (reader.hasNext()) {
        if (reader.peek() == JsonReader.Token.NAME) {
          map.put(reader.nextName(), readValue(reader));
        }
      }
      reader.endObject();

      return map;
    }
  }
}

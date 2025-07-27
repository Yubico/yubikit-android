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

package com.yubico.yubikit.testing.fido.extensions;

import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.client.extensions.Extension;
import com.yubico.yubikit.fido.client.extensions.HmacSecretExtension;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import com.yubico.yubikit.testing.fido.utils.RequestOptionsBuilder;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Assert;
import org.junit.Assume;

public class HmacSecretExtensionTests {

  private static final String KEY_HMAC_SECRET = "hmac-secret";
  private static final String KEY_HMAC_SECRET_MC = "hmac-secret-mc";
  private static final String KEY_HMAC_CREATE_SECRET = "hmacCreateSecret";
  private static final String KEY_HMAC_GET_SECRET = "hmacGetSecret";
  private static final String KEY_SALT1 = "salt1";
  private static final String KEY_SALT2 = "salt2";
  private static final String KEY_OUTPUT1 = "output1";
  private static final String KEY_OUTPUT2 = "output2";

  private static final List<Extension> extensions =
      Collections.singletonList(new HmacSecretExtension(true));

  private static final String VALUE_SALT1 =
      Base64.toUrlSafeString(
          new byte[] {
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
          });

  private final String VALUE_SALT2 =
      Base64.toUrlSafeString(
          new byte[] {
            0x01, 0x07, 0x02, 0x08, 0x03, 0x06, 0x04, 0x05,
          });

  public static void testHmacSecret(FidoTestState state) throws Throwable {
    HmacSecretExtensionTests extTests = new HmacSecretExtensionTests();
    extTests.runHmacSecretTest(state, false);
    extTests.runHmacSecretTest(state, true);
  }

  public static void testHmacSecretMc(FidoTestState state) throws Throwable {
    HmacSecretExtensionTests extTests = new HmacSecretExtensionTests();
    extTests.runHmacSecretMcTest(state, false);
    extTests.runHmacSecretMcTest(state, true);
  }

  // this test is active only on devices without hmac-secret
  public static void testNoExtensionSupport(FidoTestState state) throws Throwable {
    HmacSecretExtensionTests extTests = new HmacSecretExtensionTests();
    extTests.runNoSupportTest(state);
  }

  private HmacSecretExtensionTests() {}

  private void runHmacSecretTest(FidoTestState state, boolean rk) throws Throwable {

    // no output when no input
    state.withCtap2(
        session -> {
          Assume.assumeTrue(session.getCachedInfo().getExtensions().contains(KEY_HMAC_SECRET));
          final ClientHelper client = new ClientHelper(session, extensions);
          PublicKeyCredential cred =
              client.makeCredential(new CreationOptionsBuilder().residentKey(rk).build());
          Assert.assertNull(getCreateResult(cred));
          if (rk) {
            client.deleteCredentials(cred);
          }
        });

    // no output when hmac-secret not allowed
    // input:  { hmacSecretCreate: true }
    // output: {  }
    state.withCtap2(
        session -> {
          final ClientHelper client = new ClientHelper(session); // see that no extensions are used
          PublicKeyCredential cred =
              client.makeCredential(
                  new CreationOptionsBuilder()
                      .residentKey(rk)
                      .extensions(Collections.singletonMap(KEY_HMAC_CREATE_SECRET, true))
                      .build());

          Assert.assertNull(getCreateResult(cred));
          if (rk) {
            client.deleteCredentials(cred);
          }
        });

    // input:  { hmacSecretCreate: true }
    // output: { hmacSecretCreate: true }
    PublicKeyCredential publicKeyCredential =
        state.withCtap2(
            session -> {
              final ClientHelper client = new ClientHelper(session, extensions);
              PublicKeyCredential cred =
                  client.makeCredential(
                      new CreationOptionsBuilder()
                          .residentKey(rk)
                          .extensions(Collections.singletonMap(KEY_HMAC_CREATE_SECRET, true))
                          .build());

              Assert.assertEquals(Boolean.TRUE, getCreateResult(cred));
              return cred;
            });

    // input:  { hmacGetSecret: { salt1: String } }
    // output: { hmacGetSecret: { output1: String } }
    state.withCtap2(
        session -> {
          PublicKeyCredential cred =
              new ClientHelper(session, extensions)
                  .getAssertions(
                      new RequestOptionsBuilder()
                          // this is no discoverable key, we have to pass the id
                          .allowedCredentials(publicKeyCredential)
                          .extensions(
                              Collections.singletonMap(
                                  KEY_HMAC_GET_SECRET,
                                  Collections.singletonMap(KEY_SALT1, VALUE_SALT1)))
                          .build());

          Assert.assertNotNull(getGetResultsValue(cred, KEY_OUTPUT1));
          Assert.assertNull(getGetResultsValue(cred, KEY_OUTPUT2));
        });

    // input:  { hmacGetSecret: { salt1: String, salt2: String } }
    // output: { hmacGetSecret: { output1: String, output2: String } }
    state.withCtap2(
        session -> {
          Map<String, Object> salts = new HashMap<>();
          salts.put(KEY_SALT1, VALUE_SALT1);
          salts.put(KEY_SALT2, VALUE_SALT2);

          final ClientHelper client = new ClientHelper(session, extensions);
          PublicKeyCredential cred =
              client.getAssertions(
                  new RequestOptionsBuilder()
                      // this is no discoverable key, we have to pass the id
                      .allowedCredentials(publicKeyCredential)
                      .extensions(Collections.singletonMap(KEY_HMAC_GET_SECRET, salts))
                      .build());

          Assert.assertNotNull(getGetResultsValue(cred, KEY_OUTPUT1));
          Assert.assertNotNull(getGetResultsValue(cred, KEY_OUTPUT2));

          if (rk) {
            client.deleteCredentials(cred);
          }
        });
  }

  private void runHmacSecretMcTest(FidoTestState state, boolean rk) throws Throwable {

    // input:  { hmacSecretCreate: true, hmacGetSecret: { salt1: String } }
    // output: { hmacSecretCreate: true, hmacGetSecret: { output1: String } }
    state.withCtap2(
        session -> {
          Assume.assumeTrue(
              "No hmac-secret-mc support",
              session.getCachedInfo().getExtensions().contains(KEY_HMAC_SECRET_MC));

          Map<String, Object> extensionsInput = new HashMap<>();
          extensionsInput.put(KEY_HMAC_CREATE_SECRET, true);
          extensionsInput.put(
              KEY_HMAC_GET_SECRET, Collections.singletonMap(KEY_SALT1, VALUE_SALT1));

          final ClientHelper client = new ClientHelper(session, extensions);
          PublicKeyCredential cred =
              client.makeCredential(
                  new CreationOptionsBuilder().residentKey(rk).extensions(extensionsInput).build());
          Assert.assertEquals(Boolean.TRUE, getCreateResult(cred));
          byte[] output1 = getGetResultsValue(cred, KEY_OUTPUT1);
          Assert.assertNotNull(output1);
          Assert.assertNull(getGetResultsValue(cred, KEY_OUTPUT2));
          if (rk) {
            client.deleteCredentials(cred);
          }
        });

    // input:  { hmacSecretCreate: true, hmacGetSecret: { salt1: String, salt2: String } }
    // output: { hmacSecretCreate: true, hmacGetSecret: { output1: String, output2: String } }
    state.withCtap2(
        session -> {
          Map<String, String> salts = new HashMap<>();
          salts.put(KEY_SALT1, VALUE_SALT1);
          salts.put(KEY_SALT2, VALUE_SALT2);
          Map<String, Object> extensionsInput = new HashMap<>();
          extensionsInput.put(KEY_HMAC_CREATE_SECRET, true);
          extensionsInput.put(KEY_HMAC_GET_SECRET, salts);

          final ClientHelper client = new ClientHelper(session, extensions);
          PublicKeyCredential cred =
              client.makeCredential(
                  new CreationOptionsBuilder().residentKey(rk).extensions(extensionsInput).build());
          Assert.assertEquals(Boolean.TRUE, getCreateResult(cred));
          byte[] output1 = getGetResultsValue(cred, KEY_OUTPUT1);
          byte[] output2 = getGetResultsValue(cred, KEY_OUTPUT2);
          Assert.assertNotNull(output1);
          Assert.assertNotNull(output2);

          if (rk) {
            client.deleteCredentials(cred);
          }
        });
  }

  private void runNoSupportTest(FidoTestState state) throws Throwable {
    // input: { hmacCreateSecret: true }
    // output: { hmacCreateSecret: false }
    state.withCtap2(
        session -> {
          Assume.assumeFalse(session.getCachedInfo().getExtensions().contains(KEY_HMAC_SECRET));
          PublicKeyCredential cred =
              new ClientHelper(session, extensions)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .extensions(
                              Collections.singletonMap(
                                  KEY_HMAC_CREATE_SECRET, Collections.emptyMap()))
                          .build());

          Assert.assertEquals(Boolean.FALSE, getCreateResult(cred));
        });
  }

  @Nullable
  private Boolean getCreateResult(PublicKeyCredential credential) {
    ClientExtensionResults results = credential.getClientExtensionResults();
    Assert.assertNotNull(results);
    Map<String, Object> resultsMap = results.toMap(SerializationType.JSON);
    return (Boolean) resultsMap.get(KEY_HMAC_CREATE_SECRET);
  }

  @SuppressWarnings("unchecked")
  @Nullable
  private byte[] getGetResultsValue(PublicKeyCredential credential, String key) {
    ClientExtensionResults extensionResults = credential.getClientExtensionResults();
    Assert.assertNotNull(extensionResults);
    Map<String, Object> resultsMap = extensionResults.toMap(SerializationType.CBOR);
    Map<String, Object> getSecretMap = (Map<String, Object>) resultsMap.get(KEY_HMAC_GET_SECRET);
    Assert.assertNotNull(getSecretMap);
    return (byte[]) getSecretMap.get(key);
  }
}

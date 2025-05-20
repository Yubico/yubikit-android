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

import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import com.yubico.yubikit.testing.fido.utils.RequestOptionsBuilder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Assert;
import org.junit.Assume;

public class PrfExtensionTests {

  private static final String KEY_HMAC_SECRET = "hmac-secret";
  private static final String KEY_HMAC_SECRET_MC = "hmac-secret-mc";
  private static final String PRF_EXT = "prf";
  private static final String KEY_ENABLED = "enabled";
  private static final String KEY_EVAL = "eval";
  private static final String KEY_EVAL_BY_CREDENTIAL = "evalByCredential";
  private static final String KEY_FIRST = "first";
  private static final String KEY_SECOND = "second";

  public static void testPrf(FidoTestState state) throws Throwable {
    PrfExtensionTests extTests = new PrfExtensionTests();
    extTests.testPrf(state, false);
    extTests.testPrf(state, true);
  }

  public static void testPrfHmacSecretMc(FidoTestState state) throws Throwable {
    PrfExtensionTests extTests = new PrfExtensionTests();
    extTests.testPrfHmacSecretMc(state, false);
    extTests.testPrfHmacSecretMc(state, true);
  }

  // this test is active only on devices without hmac-secret
  public static void testNoExtensionSupport(FidoTestState state) throws Throwable {
    PrfExtensionTests extTests = new PrfExtensionTests();
    extTests.runNoSupportTest(state);
  }

  private PrfExtensionTests() {}

  private void testPrf(FidoTestState state, boolean rk) throws Throwable {
    {
      // no output when no input
      state.withCtap2(
          session -> {
            Assume.assumeTrue(session.getCachedInfo().getExtensions().contains(KEY_HMAC_SECRET));
            ClientHelper client = new ClientHelper(session);
            PublicKeyCredential cred =
                client.makeCredential(new CreationOptionsBuilder().residentKey(rk).build());
            Assert.assertNull(getResult(cred));
            if (rk) {
              client.deleteCredentials(cred);
            }
          });

      // input:  { prf: {} }
      // output: { prf: { enabled: true } }
      PublicKeyCredential publicKeyCredential =
          state.withCtap2(
              session -> {
                PublicKeyCredential cred =
                    new ClientHelper(session)
                        .makeCredential(
                            new CreationOptionsBuilder()
                                .residentKey(rk)
                                .extensions(
                                    Collections.singletonMap(PRF_EXT, Collections.emptyMap()))
                                .build());
                Assert.assertEquals(Boolean.TRUE, getResultValue(cred, KEY_ENABLED));
                return cred;
              });

      // input:  { prf: { eval: { first: String } } }
      // output: { prf: { results: { first: String } } }
      state.withCtap2(
          session -> {
            RequestOptionsBuilder requestOptionsBuilder =
                new RequestOptionsBuilder()
                    .extensions(
                        Collections.singletonMap(
                            PRF_EXT,
                            Collections.singletonMap(
                                KEY_EVAL, Collections.singletonMap(KEY_FIRST, "abba"))));

            if (!rk) {
              requestOptionsBuilder.allowedCredentials(publicKeyCredential);
            }

            PublicKeyCredential cred =
                new ClientHelper(session).getAssertions(requestOptionsBuilder.build());
            Assert.assertNull(getResultValue(cred, KEY_ENABLED));
            Assert.assertTrue(getResultsValue(cred, KEY_FIRST) instanceof String);
            Assert.assertNull(getResultsValue(cred, KEY_SECOND));
          });

      // input:  { prf: { eval: { first: String, second: String } } }
      // output: { prf: { results: { first: String, second: String } } }
      state.withCtap2(
          session -> {
            Map<String, Object> eval = new HashMap<>();
            eval.put(KEY_FIRST, "abba");
            eval.put(KEY_SECOND, "bebe");

            RequestOptionsBuilder requestOptionsBuilder =
                new RequestOptionsBuilder()
                    .extensions(
                        Collections.singletonMap(
                            PRF_EXT, Collections.singletonMap(KEY_EVAL, eval)));

            if (!rk) {
              requestOptionsBuilder.allowedCredentials(publicKeyCredential);
            }

            ClientHelper client = new ClientHelper(session);
            PublicKeyCredential cred = client.getAssertions(requestOptionsBuilder.build());
            Assert.assertNull(getResultValue(cred, KEY_ENABLED));
            Assert.assertTrue(getResultsValue(cred, KEY_FIRST) instanceof String);
            Assert.assertTrue(getResultsValue(cred, KEY_SECOND) instanceof String);

            if (rk) {
              client.deleteCredentials(publicKeyCredential);
            }
          });
    }
  }

  private void testPrfHmacSecretMc(FidoTestState state, boolean rk) throws Throwable {
    {
      // input:  { prf: { eval: { first: String } } }
      // output: { prf: { enabled: true, results: { first: String } }
      List<Object> results1 =
          state.withCtap2(
              session -> {
                Assume.assumeTrue(
                    session.getCachedInfo().getExtensions().contains(KEY_HMAC_SECRET_MC));
                PublicKeyCredential cred =
                    new ClientHelper(session)
                        .makeCredential(
                            new CreationOptionsBuilder()
                                .residentKey(rk)
                                .extensions(
                                    Collections.singletonMap(
                                        PRF_EXT,
                                        Collections.singletonMap(
                                            KEY_EVAL, Collections.singletonMap(KEY_FIRST, "abba"))))
                                .build());
                Assert.assertEquals(Boolean.TRUE, getResultValue(cred, KEY_ENABLED));
                Object firstValue = getResultsValue(cred, KEY_FIRST);
                Assert.assertTrue(firstValue instanceof String);

                List<Object> results = new ArrayList<>();
                results.add(cred);
                results.add(firstValue);
                return results;
              });

      // input:  { prf: { eval: { first: String } } }
      // output: { prf: { results: { first: String } } }
      state.withCtap2(
          session -> {
            RequestOptionsBuilder requestOptionsBuilder =
                new RequestOptionsBuilder()
                    .extensions(
                        Collections.singletonMap(
                            PRF_EXT,
                            Collections.singletonMap(
                                KEY_EVAL, Collections.singletonMap(KEY_FIRST, "abba"))));

            if (!rk) {
              requestOptionsBuilder.allowedCredentials((PublicKeyCredential) results1.get(0));
            }

            final ClientHelper client = new ClientHelper(session);
            PublicKeyCredential cred = client.getAssertions(requestOptionsBuilder.build());

            Assert.assertNull(getResultValue(cred, KEY_ENABLED));
            Object firstValue = getResultsValue(cred, KEY_FIRST);
            Assert.assertTrue(firstValue instanceof String);
            Assert.assertNull(getResultsValue(cred, KEY_SECOND));

            // Output is stable per input
            Assert.assertEquals(results1.get(1), firstValue);

            if (rk) {
              client.deleteCredentials((PublicKeyCredential) results1.get(0));
            }
          });

      // input:  { prf: { eval: { first: String, second: String } } }
      // output: { prf: { enabled: true, results: { first: String, second: String } }
      List<Object> results2 =
          state.withCtap2(
              session -> {
                Map<String, Object> eval = new HashMap<>();
                eval.put(KEY_FIRST, "abba");
                eval.put(KEY_SECOND, "bebe");

                CreationOptionsBuilder creationOptionsBuilder =
                    new CreationOptionsBuilder()
                        .residentKey(rk)
                        .extensions(
                            Collections.singletonMap(
                                PRF_EXT, Collections.singletonMap(KEY_EVAL, eval)));

                PublicKeyCredential cred =
                    new ClientHelper(session).makeCredential(creationOptionsBuilder.build());

                Assert.assertEquals(Boolean.TRUE, getResultValue(cred, KEY_ENABLED));
                Object firstValue = getResultsValue(cred, KEY_FIRST);
                Object secondValue = getResultsValue(cred, KEY_SECOND);
                Assert.assertTrue(firstValue instanceof String);
                Assert.assertTrue(secondValue instanceof String);

                List<Object> results = new ArrayList<>();
                results.add(cred);
                results.add(firstValue);
                results.add(secondValue);
                return results;
              });

      // input:  { prf: { eval: { first: String, second: String } } }
      // output: { prf: { results: { first: String, second: String } } }
      state.withCtap2(
          session -> {
            Map<String, Object> eval = new HashMap<>();
            eval.put(KEY_FIRST, "abba");
            eval.put(KEY_SECOND, "bebe");

            RequestOptionsBuilder requestOptionsBuilder =
                new RequestOptionsBuilder()
                    .extensions(
                        Collections.singletonMap(
                            PRF_EXT, Collections.singletonMap(KEY_EVAL, eval)));

            if (!rk) {
              requestOptionsBuilder.allowedCredentials((PublicKeyCredential) results2.get(0));
            }

            ClientHelper client = new ClientHelper(session);
            PublicKeyCredential cred = client.getAssertions(requestOptionsBuilder.build());
            Assert.assertNull(getResultValue(cred, KEY_ENABLED));
            Object firstValue = getResultsValue(cred, KEY_FIRST);
            Object secondValue = getResultsValue(cred, KEY_SECOND);
            Assert.assertTrue(firstValue instanceof String);
            Assert.assertTrue(secondValue instanceof String);

            // Output is stable per input
            Assert.assertEquals(results2.get(1), firstValue);
            Assert.assertEquals(results2.get(2), secondValue);

            if (rk) {
              client.deleteCredentials((PublicKeyCredential) results2.get(0));
            }
          });
    }
  }

  private void runNoSupportTest(FidoTestState state) throws Throwable {
    // input:  { prf: {} }
    // output: { prf: { enabled: false } }
    state.withCtap2(
        session -> {
          Assume.assumeFalse(session.getCachedInfo().getExtensions().contains(KEY_HMAC_SECRET));
          PublicKeyCredential cred =
              new ClientHelper(session)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .extensions(Collections.singletonMap(PRF_EXT, Collections.emptyMap()))
                          .build());
          Map<String, ?> result = getResult(cred);
          Assert.assertNotNull(result);
          Assert.assertEquals(Boolean.FALSE, result.get(KEY_ENABLED));
        });
  }

  @SuppressWarnings("unchecked")
  @Nullable
  private Object getResultsValue(PublicKeyCredential credential, String key) {
    String KEY_RESULTS = "results";
    Map<String, ?> results = (Map<String, ?>) getResultValue(credential, KEY_RESULTS);
    Assert.assertNotNull(results);
    return results.get(key);
  }

  @Nullable
  private Object getResultValue(PublicKeyCredential credential, String key) {
    Map<String, ?> prf = getResult(credential);
    Assert.assertNotNull(prf);
    return prf.get(key);
  }

  @SuppressWarnings("unchecked")
  @Nullable
  private Map<String, ?> getResult(PublicKeyCredential credential) {
    ClientExtensionResults results = credential.getClientExtensionResults();
    Assert.assertNotNull(results);
    Map<String, Object> resultsMap = results.toMap(SerializationType.JSON);
    return (Map<String, ?>) resultsMap.get(PRF_EXT);
  }
}

/*
 * Copyright (C) 2024-2026 Yubico.
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

import com.yubico.yubikit.fido.FidoTestState;
import com.yubico.yubikit.fido.utils.ClientHelper;
import com.yubico.yubikit.fido.utils.CreationOptionsBuilder;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.junit.Assert;
import org.junit.Assume;

public class SignExtensionTests {

  private static final String SIGN_EXT = "previewSign";

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
            Assert.assertNull(getSignResult(cred, SerializationType.JSON));
            if (residentKey) {
              new ClientHelper(session, extensions).deleteCredentials(cred);
            }
          });

      // create credential with generateKey
      state.withCtap2(
          session -> {
            PublicKeyCredential cred =
                new ClientHelper(session, extensions)
                    .makeCredential(
                        new CreationOptionsBuilder()
                            .residentKey(residentKey)
                            .extensions(
                                Collections.singletonMap(
                                    SIGN_EXT,
                                    Collections.singletonMap(
                                        "generateKey",
                                        Collections.singletonMap(
                                            "algorithms", Arrays.asList(-65600, -65539, -9, -7)))))
                            .build());

            Map<String, Object> signCreateResultJson = getSignResult(cred, SerializationType.JSON);
            Assert.assertNotNull(signCreateResultJson);
            assertGeneratedKeyPresent(signCreateResultJson);
            Map<String, Object> generatedKeyJson =
                (Map<String, Object>) signCreateResultJson.get("generatedKey");
            Assert.assertTrue(generatedKeyJson.get("keyHandle") instanceof String);
            Assert.assertTrue(generatedKeyJson.get("publicKey") instanceof String);
            Assert.assertTrue(generatedKeyJson.get("attestationObject") instanceof String);

            Map<String, Object> signCreateResultCbor = getSignResult(cred, SerializationType.CBOR);
            Assert.assertNotNull(signCreateResultCbor);
            assertGeneratedKeyPresent(signCreateResultCbor);
            Map<String, Object> generatedKeyCbor =
                (Map<String, Object>) signCreateResultCbor.get("generatedKey");
            Assert.assertTrue(generatedKeyCbor.get("keyHandle") instanceof byte[]);
            Assert.assertTrue(generatedKeyCbor.get("publicKey") instanceof byte[]);
            Assert.assertTrue(generatedKeyCbor.get("attestationObject") instanceof byte[]);

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

          Assert.assertNull(getSignResult(cred, SerializationType.JSON));
        });
  }

  @SuppressWarnings("unchecked")
  @Nullable
  private Map<String, Object> getSignResult(
      PublicKeyCredential credential, SerializationType serializationType) {
    ClientExtensionResults results = credential.getClientExtensionResults();
    Assert.assertNotNull(results);
    Map<String, Object> resultsMap = results.toMap(serializationType);
    return (Map<String, Object>) resultsMap.get(SIGN_EXT);
  }

  @SuppressWarnings("unchecked")
  private void assertGeneratedKeyPresent(Map<String, Object> signResult) {
    Assert.assertFalse(signResult.containsKey("signature"));
    Map<String, Object> generatedKey = (Map<String, Object>) signResult.get("generatedKey");
    Assert.assertNotNull(generatedKey);
    Assert.assertTrue(generatedKey.containsKey("keyHandle"));
    Assert.assertTrue(generatedKey.containsKey("publicKey"));
    Assert.assertTrue(generatedKey.containsKey("algorithm"));
    Assert.assertTrue(generatedKey.containsKey("attestationObject"));
  }
}

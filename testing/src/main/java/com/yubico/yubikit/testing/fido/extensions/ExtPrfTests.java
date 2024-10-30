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
import com.yubico.yubikit.fido.webauthn.Extension;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import com.yubico.yubikit.testing.fido.utils.RequestOptionsBuilder;

import org.junit.Assert;
import org.junit.Assume;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nullable;

public class ExtPrfTests {

    private final String KEY_HMAC_SECRET = "hmac-secret";
    private final String PRF_EXT = "prf";
    private final String KEY_ENABLED = "enabled";
    private final String KEY_EVAL = "eval";
    private final String KEY_EVAL_BY_CREDENTIAL = "evalByCredential";
    private final String KEY_FIRST = "first";
    private final String KEY_SECOND = "second";

    public static void test(FidoTestState state) throws Throwable {
        ExtPrfTests extTests = new ExtPrfTests();
        extTests.runTest(state);
    }

    // this test is active only on devices without hmac-secret
    public static void testNoExtensionSupport(FidoTestState state) throws Throwable {
        ExtPrfTests extTests = new ExtPrfTests();
        extTests.runNoSupportTest(state);
    }

    private ExtPrfTests() {

    }

    private void runTest(FidoTestState state) throws Throwable {

        // non-discoverable credential
        {
            // no output when no input
            state.withCtap2(session -> {
                Assume.assumeTrue(session.getCachedInfo().getExtensions()
                        .contains(KEY_HMAC_SECRET));
                PublicKeyCredential cred = new ClientHelper(session).makeCredential();
                Map<String, ?> result = getResult(cred);
                Assert.assertNull(result);
            });

            // input:  { prf: {} }
            // output: { prf: { enabled: true } }
            PublicKeyCredential publicKeyCredential = state.withCtap2(session -> {
                PublicKeyCredential cred = new ClientHelper(session)
                        .makeCredential(
                                new CreationOptionsBuilder()
                                        .extensions(Collections.singletonMap(PRF_EXT, Collections.emptyMap()))
                                        .build()
                        );

                Assert.assertEquals(Boolean.TRUE, getResultValue(cred, KEY_ENABLED));
                return cred;
            });

            // input:  { prf: { eval: { first: String } } }
            // output: { prf: { results: { first: String } } }
            state.withCtap2(session -> {
                PublicKeyCredential cred = new ClientHelper(session)
                        .getAssertions(
                                new RequestOptionsBuilder()
                                        // this is no discoverable key, we have to pass the id
                                        .allowedCredentials(publicKeyCredential)
                                        .extensions(Collections.singletonMap(PRF_EXT,
                                                Collections.singletonMap(KEY_EVAL,
                                                        Collections.singletonMap(KEY_FIRST, "abba"))))
                                        .build()
                        );

                Assert.assertNull(getResultValue(cred, KEY_ENABLED));
                Assert.assertTrue(getResultsValue(cred, KEY_FIRST) instanceof String);
                Assert.assertNull(getResultsValue(cred, KEY_SECOND));
            });

            // input:  { prf: { eval: { first: String, second: String } } }
            // output: { prf: { results: { first: String, second: String } } }
            state.withCtap2(session -> {

                Map<String, Object> eval = new HashMap<>();
                eval.put(KEY_FIRST, "abba");
                eval.put(KEY_SECOND, "bebe");

                PublicKeyCredential cred = new ClientHelper(session)
                        .getAssertions(
                                new RequestOptionsBuilder()
                                        // this is no discoverable key, we have to pass the id
                                        .allowedCredentials(publicKeyCredential)
                                        .extensions(Collections.singletonMap(PRF_EXT,
                                                Collections.singletonMap(KEY_EVAL, eval)))
                                        .build()
                        );

                Assert.assertNull(getResultValue(cred, KEY_ENABLED));
                Assert.assertTrue(getResultsValue(cred, KEY_FIRST) instanceof String);
                Assert.assertTrue(getResultsValue(cred, KEY_SECOND) instanceof String);

            });


            // create 2 more credentials
            PublicKeyCredential publicKeyCredential2 = state.withCtap2(session -> {
                PublicKeyCredential cred = new ClientHelper(session)
                        .makeCredential(
                                new CreationOptionsBuilder()
                                        .extensions(Collections.singletonMap(PRF_EXT, Collections.emptyMap()))
                                        .build()
                        );

                Assert.assertEquals(Boolean.TRUE, getResultValue(cred, KEY_ENABLED));
                return cred;
            });

            PublicKeyCredential publicKeyCredential3 = state.withCtap2(session -> {
                PublicKeyCredential cred = new ClientHelper(session)
                        .makeCredential(
                                new CreationOptionsBuilder()
                                        .extensions(Collections.singletonMap(PRF_EXT, Collections.emptyMap()))
                                        .build()
                        );

                Assert.assertEquals(Boolean.TRUE, getResultValue(cred, KEY_ENABLED));
                return cred;
            });

            // evalByCredential
            state.withCtap2(session -> {
                Map<String, Object> evalByCredential = new HashMap<>();
                evalByCredential.put(
                        Base64.toUrlSafeString(publicKeyCredential3.getRawId()),
                        Collections.singletonMap(KEY_FIRST, "abba"));
                evalByCredential.put(
                        Base64.toUrlSafeString(publicKeyCredential2.getRawId()),
                        Collections.singletonMap(KEY_FIRST, "bebe"));
                evalByCredential.put(
                        Base64.toUrlSafeString(publicKeyCredential.getRawId()),
                        Collections.singletonMap(KEY_FIRST, "cece"));


                PublicKeyCredential cred = new ClientHelper(session)
                        .getAssertions(
                                new RequestOptionsBuilder()
                                        // evalByCredential requires allow list
                                        .allowedCredentials(
                                                publicKeyCredential,
                                                publicKeyCredential2,
                                                publicKeyCredential3)
                                        .extensions(Collections.singletonMap(PRF_EXT,
                                                Collections.singletonMap(KEY_EVAL_BY_CREDENTIAL,
                                                        evalByCredential
                                                )))
                                        .build()
                        );

                Assert.assertNull(getResultValue(cred, KEY_ENABLED));
                Assert.assertTrue(getResultsValue(cred, KEY_FIRST) instanceof String);
                Assert.assertNull(getResultsValue(cred, KEY_SECOND));
            });


        }

        // discoverable credential
        {
            // no output when no input
            state.withCtap2(session -> {
                Assume.assumeTrue(session.getCachedInfo().getExtensions()
                        .contains(KEY_HMAC_SECRET));
                ClientHelper client = new ClientHelper(session);
                PublicKeyCredential cred = client.makeCredential(
                        new CreationOptionsBuilder()
                                .residentKey(true)
                                .build()
                );
                Assert.assertNull(getResult(cred));
                client.deleteCredentials(cred);
            });

            // input:  { prf: {} }
            // output: { prf: { enabled: true } }
            PublicKeyCredential publicKeyCredential = state.withCtap2(session -> {
                PublicKeyCredential cred = new ClientHelper(session)
                        .makeCredential(
                                new CreationOptionsBuilder()
                                        .residentKey(true)
                                        .extensions(Collections.singletonMap(PRF_EXT,
                                                Collections.emptyMap()))
                                        .build()
                        );
                Assert.assertEquals(Boolean.TRUE, getResultValue(cred, KEY_ENABLED));
                return cred;
            });

            // input:  { prf: { eval: { first: String } } }
            // output: { prf: { results: { first: String } } }
            state.withCtap2(session -> {
                PublicKeyCredential cred = new ClientHelper(session)
                        .getAssertions(
                                new RequestOptionsBuilder()
                                        .extensions(Collections.singletonMap(PRF_EXT,
                                                Collections.singletonMap(KEY_EVAL,
                                                        Collections.singletonMap(KEY_FIRST, "abba"))))
                                        .build()
                        );
                Assert.assertNull(getResultValue(cred, KEY_ENABLED));
                Assert.assertTrue(getResultsValue(cred, KEY_FIRST) instanceof String);
                Assert.assertNull(getResultsValue(cred, KEY_SECOND));
            });

            // input:  { prf: { eval: { first: String, second: String } } }
            // output: { prf: { results: { first: String, second: String } } }
            state.withCtap2(session -> {

                Map<String, Object> eval = new HashMap<>();
                eval.put(KEY_FIRST, "abba");
                eval.put(KEY_SECOND, "bebe");

                ClientHelper client = new ClientHelper(session);
                PublicKeyCredential cred = client.getAssertions(
                        new RequestOptionsBuilder()
                                .extensions(Collections.singletonMap(PRF_EXT,
                                        Collections.singletonMap(KEY_EVAL, eval)))
                                .build()
                );
                Assert.assertNull(getResultValue(cred, KEY_ENABLED));
                Assert.assertTrue(getResultsValue(cred, KEY_FIRST) instanceof String);
                Assert.assertTrue(getResultsValue(cred, KEY_SECOND) instanceof String);

                client.deleteCredentials(publicKeyCredential);
            });
        }
    }

    private void runNoSupportTest(FidoTestState state) throws Throwable {
        // input:  { prf: {} }
        // output: { prf: { enabled: false } }
        state.withCtap2(session -> {
            Assume.assumeFalse(session.getCachedInfo().getExtensions().contains(KEY_HMAC_SECRET));
            PublicKeyCredential cred = new ClientHelper(session)
                    .makeCredential(
                            new CreationOptionsBuilder()
                                    .extensions(Collections.singletonMap(PRF_EXT,
                                            Collections.emptyMap()))
                                    .build()
                    );
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
        Extension.ExtensionResults results = credential.getClientExtensionResults();
        Assert.assertNotNull(results);
        Map<String, Object> resultsMap = results.toMap();
        return (Map<String, ?>) resultsMap.get(PRF_EXT);
    }
}

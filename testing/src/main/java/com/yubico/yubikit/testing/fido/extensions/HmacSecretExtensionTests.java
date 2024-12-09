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
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.SerializationType;
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

public class HmacSecretExtensionTests {

    private static final String KEY_HMAC_SECRET = "hmac-secret";
    private static final String KEY_HMAC_CREATE_SECRET = "hmacCreateSecret";
    private static final String KEY_HMAC_GET_SECRET = "hmacGetSecret";
    private static final String KEY_SALT1 = "salt1";
    private static final String KEY_SALT2 = "salt2";
    private static final String KEY_OUTPUT1 = "output1";
    private static final String KEY_OUTPUT2 = "output2";

    private static final String VALUE_SALT1 = Base64.toUrlSafeString(new byte[]{
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
    });

    private final String VALUE_SALT2 = Base64.toUrlSafeString(new byte[]{
            0x01, 0x07, 0x02, 0x08, 0x03, 0x06, 0x04, 0x05,
    });

    public static void test(FidoTestState state) throws Throwable {
        HmacSecretExtensionTests extTests = new HmacSecretExtensionTests();
        extTests.runTest(state);
    }

    // this test is active only on devices without hmac-secret
    public static void testNoExtensionSupport(FidoTestState state) throws Throwable {
        HmacSecretExtensionTests extTests = new HmacSecretExtensionTests();
        extTests.runNoSupportTest(state);
    }

    private HmacSecretExtensionTests() {

    }

    private void runTest(FidoTestState state) throws Throwable {

        // non-discoverable credential
        {
            // no output when no input
            state.withCtap2(session -> {
                Assume.assumeTrue(session.getCachedInfo().getExtensions()
                        .contains(KEY_HMAC_SECRET));
                PublicKeyCredential cred = new ClientHelper(session).makeCredential();
                Assert.assertNull(getCreateResult(cred));
            });

            // input:  { hmacSecretCreate: true }
            // output: { hmacSecretCreate: true }
            PublicKeyCredential publicKeyCredential = state.withCtap2(session -> {
                PublicKeyCredential cred = new ClientHelper(session).makeCredential(
                        new CreationOptionsBuilder()
                                .extensions(Collections.singletonMap(KEY_HMAC_CREATE_SECRET, true))
                                .build()
                );

                Assert.assertEquals(Boolean.TRUE, getCreateResult(cred));
                return cred;
            });

            // input:  { hmacGetSecret: { salt1: String } }
            // output: { hmacGetSecret: { output1: String } }
            state.withCtap2(session -> {
                PublicKeyCredential cred = new ClientHelper(session)
                        .getAssertions(
                                new RequestOptionsBuilder()
                                        // this is no discoverable key, we have to pass the id
                                        .allowedCredentials(publicKeyCredential)
                                        .extensions(Collections.singletonMap(KEY_HMAC_GET_SECRET,
                                                Collections.singletonMap(KEY_SALT1, VALUE_SALT1)))
                                        .build()
                        );

                Assert.assertNotNull(getGetResultsValue(cred, KEY_OUTPUT1));
                Assert.assertNull(getGetResultsValue(cred, KEY_OUTPUT2));
            });

            // input:  { hmacGetSecret: { salt1: String, salt2: String } }
            // output: { hmacGetSecret: { output1: String, output2: String } }
            state.withCtap2(session -> {

                Map<String, Object> salts = new HashMap<>();
                salts.put(KEY_SALT1, VALUE_SALT1);
                salts.put(KEY_SALT2, VALUE_SALT2);

                PublicKeyCredential cred = new ClientHelper(session).getAssertions(
                        new RequestOptionsBuilder()
                                // this is no discoverable key, we have to pass the id
                                .allowedCredentials(publicKeyCredential)
                                .extensions(
                                        Collections.singletonMap(KEY_HMAC_GET_SECRET, salts))
                                .build()
                );

                Assert.assertNotNull(getGetResultsValue(cred, KEY_OUTPUT1));
                Assert.assertNotNull(getGetResultsValue(cred, KEY_OUTPUT2));
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
                Assert.assertNull(getCreateResult(cred));
                client.deleteCredentials(cred);
            });

            // input:  { hmacSecretCreate: true }
            // output: { hmacSecretCreate: true }
            PublicKeyCredential publicKeyCredential = state.withCtap2(session -> {
                PublicKeyCredential cred = new ClientHelper(session).makeCredential(
                        new CreationOptionsBuilder()
                                .residentKey(true)
                                .extensions(Collections.singletonMap(KEY_HMAC_CREATE_SECRET, true))
                                .build()
                );
                Assert.assertEquals(Boolean.TRUE, getCreateResult(cred));
                return cred;
            });

            // input:  { hmacGetSecret: { salt1: String } }
            // output: { hmacGetSecret: { output1: String } }
            state.withCtap2(session -> {
                PublicKeyCredential cred = new ClientHelper(session)
                        .getAssertions(
                                new RequestOptionsBuilder()
                                        .extensions(Collections.singletonMap(KEY_HMAC_GET_SECRET,
                                                Collections.singletonMap(KEY_SALT1, VALUE_SALT1)))
                                        .build()
                        );
                Assert.assertNotNull(getGetResultsValue(cred, KEY_OUTPUT1));
                Assert.assertNull(getGetResultsValue(cred, KEY_OUTPUT2));
            });

            // input:  { hmacGetSecret: { salt1: String, salt2: String } }
            // output: { hmacGetSecret: { output1: String, output2: String } }
            state.withCtap2(session -> {

                Map<String, Object> salts = new HashMap<>();
                salts.put(KEY_SALT1, VALUE_SALT1);
                salts.put(KEY_SALT2, VALUE_SALT2);

                ClientHelper client = new ClientHelper(session);
                PublicKeyCredential cred = client.getAssertions(
                        new RequestOptionsBuilder()
                                .extensions(
                                        Collections.singletonMap(KEY_HMAC_GET_SECRET, salts))
                                .build()
                );

                Assert.assertNotNull(getGetResultsValue(cred, KEY_OUTPUT1));
                Assert.assertNotNull(getGetResultsValue(cred, KEY_OUTPUT2));

                client.deleteCredentials(publicKeyCredential);
            });
        }
    }

    private void runNoSupportTest(FidoTestState state) throws Throwable {
        // input: { hmacCreateSecret: true }
        // output: { hmacCreateSecret: false }
        state.withCtap2(session -> {
            Assume.assumeFalse(session.getCachedInfo().getExtensions().contains(KEY_HMAC_SECRET));
            PublicKeyCredential cred = new ClientHelper(session)
                    .makeCredential(
                            new CreationOptionsBuilder()
                                    .extensions(
                                            Collections.singletonMap(KEY_HMAC_CREATE_SECRET,
                                                    Collections.emptyMap()))
                                    .build()
                    );

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

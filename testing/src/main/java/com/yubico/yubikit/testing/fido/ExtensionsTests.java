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

package com.yubico.yubikit.testing.fido;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.client.BasicWebAuthnClient;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.client.CredentialManager;
import com.yubico.yubikit.fido.client.MultipleAssertionsAvailable;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.Extension;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import com.yubico.yubikit.fido.webauthn.SerializationType;

import org.junit.Assert;
import org.junit.Assume;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class ExtensionsTests {

    public static void testCredPropsExtension(FidoTestState state) throws Throwable {
        final String CRED_PROPS = "credProps";

        // no output in results if extension not requested
        state.withCtap2(session -> {
            BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
            PublicKeyCredential cred = new Builder(webauthn).create();
            Map<String, ?> result = getResult(cred.getClientExtensionResults(), CRED_PROPS);
            Assert.assertNull(result);
        });

        // rk value is correct (false) during registration
        state.withCtap2(session -> {
            BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

            PublicKeyCredential cred = new Builder(webauthn)
                    .residentKey(false)
                    .extensions(Collections.singletonMap(CRED_PROPS, true))
                    .create();

            Map<String, ?> result = getResult(cred.getClientExtensionResults(), CRED_PROPS);
            Assert.assertNotNull(result);
            Assert.assertEquals(Boolean.FALSE, result.get("rk"));
        });

        // rk value is correct (true) during registration
        state.withCtap2(session -> {
            BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

            PublicKeyCredential cred = new Builder(webauthn)
                    .residentKey(true)
                    .extensions(Collections.singletonMap(CRED_PROPS, true))
                    .create();

            Map<String, ?> result = getResult(cred.getClientExtensionResults(), CRED_PROPS);
            Assert.assertNotNull(result);
            Assert.assertEquals(Boolean.TRUE, result.get("rk"));
            deleteCredentials(webauthn, Collections.singletonList(cred.getRawId()));
        });
    }

    @SuppressWarnings("unchecked")
    public static void testPrfExtension(FidoTestState state) throws Throwable {
        final String PRF_EXT = "prf";

        // non-discoverable credential
        {
            // no output when no input
            state.withCtap2(session -> {
                Assume.assumeTrue(session.getCachedInfo().getExtensions().contains("hmac-secret"));
                BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
                PublicKeyCredential cred = new Builder(webauthn).create();
                Map<String, ?> result = getResult(cred.getClientExtensionResults(), PRF_EXT);
                Assert.assertNull(result);
            });

            // { prf: { enabled: true } }
            PublicKeyCredentialDescriptor credDesc = state.withCtap2(session -> {
                BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
                PublicKeyCredential cred = new Builder(webauthn)
                        .extensions(Collections.singletonMap(PRF_EXT, Collections.emptyMap()))
                        .create();
                Map<String, ?> result = getResult(cred.getClientExtensionResults(), PRF_EXT);
                Assert.assertNotNull(result);
                Assert.assertEquals(Boolean.TRUE, result.get("enabled"));
                return new PublicKeyCredentialDescriptor("public-key", cred.getRawId());
            });

            // assertion with { eval: { first: "value" } }
            // { prf: { results: { first: String } } }
            state.withCtap2(session -> {
                BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
                PublicKeyCredential cred = new Builder(webauthn)
                        // this is no discoverable key, we have to pass the id
                        .allowedCredentials(Collections.singletonList(credDesc))
                        .extensions(Collections.singletonMap(PRF_EXT,
                                Collections.singletonMap("eval",
                                        Collections.singletonMap("first", "abba"))))
                        .getAssertions();
                Map<String, ?> result = getResult(cred.getClientExtensionResults(), PRF_EXT);
                Assert.assertNotNull(result);
                Assert.assertFalse(result.containsKey("enabled"));
                Assert.assertTrue(result.containsKey("results"));
                Map<String, ?> results = (Map<String, ?>) result.get("results");
                Assert.assertTrue(results.containsKey("first"));
                Assert.assertTrue(results.get("first") instanceof String);
                Assert.assertFalse(results.containsKey("second"));
            });

            // assertion with { eval: { first: "value", second: "value" } }
            // { prf: { results: { first: String, second: String } } }
            state.withCtap2(session -> {
                BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

                Map<String, Object> eval = new HashMap<>();
                eval.put("first", "abba");
                eval.put("second", "bebe");

                PublicKeyCredential cred = new Builder(webauthn)
                        // this is no discoverable key, we have to pass the id
                        .allowedCredentials(Collections.singletonList(credDesc))
                        .extensions(Collections.singletonMap(PRF_EXT,
                                Collections.singletonMap("eval", eval)))
                        .getAssertions();
                Map<String, ?> result = getResult(cred.getClientExtensionResults(), PRF_EXT);
                Assert.assertNotNull(result);
                Assert.assertFalse(result.containsKey("enabled"));
                Assert.assertTrue(result.containsKey("results"));
                Map<String, ?> results = (Map<String, ?>) result.get("results");
                Assert.assertTrue(results.containsKey("first"));
                Assert.assertTrue(results.get("first") instanceof String);
                Assert.assertTrue(results.containsKey("second"));
                Assert.assertTrue(results.get("second") instanceof String);
            });
        }

        // discoverable credential
        {
            // no output when no input
            state.withCtap2(session -> {
                Assume.assumeTrue(session.getCachedInfo().getExtensions().contains("hmac-secret"));
                BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
                PublicKeyCredential cred = new Builder(webauthn).residentKey(true).create();
                Map<String, ?> result = getResult(cred.getClientExtensionResults(), PRF_EXT);
                Assert.assertNull(result);
                deleteCredentials(webauthn, Collections.singletonList(cred.getRawId()));
            });

            // { prf: { enabled: true } }
            PublicKeyCredentialDescriptor credDesc = state.withCtap2(session -> {
                BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
                PublicKeyCredential cred = new Builder(webauthn)
                        .residentKey(true)
                        .extensions(Collections.singletonMap(PRF_EXT, Collections.emptyMap()))
                        .create();
                Map<String, ?> result = getResult(cred.getClientExtensionResults(), PRF_EXT);
                Assert.assertNotNull(result);
                Assert.assertEquals(Boolean.TRUE, result.get("enabled"));
                return new PublicKeyCredentialDescriptor("public-key", cred.getRawId());
            });

            // assertion with { eval: { first: "value" } }
            // { prf: { results: { first: String } } }
            state.withCtap2(session -> {
                BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
                PublicKeyCredential cred = new Builder(webauthn)
                        .extensions(Collections.singletonMap(PRF_EXT,
                                Collections.singletonMap("eval",
                                        Collections.singletonMap("first", "abba"))))
                        .getAssertions();
                Map<String, ?> result = getResult(cred.getClientExtensionResults(), PRF_EXT);
                Assert.assertNotNull(result);
                Assert.assertFalse(result.containsKey("enabled"));
                Assert.assertTrue(result.containsKey("results"));
                Map<String, ?> results = (Map<String, ?>) result.get("results");
                Assert.assertTrue(results.containsKey("first"));
                Assert.assertTrue(results.get("first") instanceof String);
                Assert.assertFalse(results.containsKey("second"));
            });

            // assertion with { eval: { first: "value", second: "value" } }
            // { prf: { results: { first: String, second: String } } }
            state.withCtap2(session -> {
                BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

                Map<String, Object> eval = new HashMap<>();
                eval.put("first", "abba");
                eval.put("second", "bebe");

                PublicKeyCredential cred = new Builder(webauthn)
                        .extensions(Collections.singletonMap(PRF_EXT,
                                Collections.singletonMap("eval", eval)))
                        .getAssertions();
                Map<String, ?> result = getResult(cred.getClientExtensionResults(), PRF_EXT);
                Assert.assertNotNull(result);
                Assert.assertFalse(result.containsKey("enabled"));
                Assert.assertTrue(result.containsKey("results"));
                Map<String, ?> results = (Map<String, ?>) result.get("results");
                Assert.assertTrue(results.containsKey("first"));
                Assert.assertTrue(results.get("first") instanceof String);
                Assert.assertTrue(results.containsKey("second"));
                Assert.assertTrue(results.get("second") instanceof String);

                deleteCredentials(webauthn, Collections.singletonList(credDesc.getId()));
            });
        }
    }

    // this test is active only on devices without hmac-secret
    public static void testPrfExtensionNoSupport(FidoTestState state) throws Throwable {
        final String PRF_EXT = "prf";

        // { prf: { enabled: false } }
        state.withCtap2(session -> {
            Assume.assumeFalse(session.getCachedInfo().getExtensions().contains("hmac-secret"));
            BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
            PublicKeyCredential cred = new Builder(webauthn)
                    .extensions(Collections.singletonMap(PRF_EXT, Collections.emptyMap()))
                    .create();
            Map<String, ?> result = getResult(cred.getClientExtensionResults(), PRF_EXT);
            Assert.assertNotNull(result);
            Assert.assertEquals(Boolean.FALSE, result.get("enabled"));
        });
    }

    static class Builder {
        final BasicWebAuthnClient client;

        List<PublicKeyCredentialDescriptor> allowedCredentials = null;
        boolean residentKey = false;

        @Nullable
        Extensions extensions = null;

        Builder(BasicWebAuthnClient client) {
            this.client = client;
        }

        Builder residentKey(boolean residentKey) {
            this.residentKey = residentKey;
            return this;
        }

        Builder extensions(@Nullable Map<String, ?> extensions) {
            this.extensions = extensions == null
                    ? null
                    : Extensions.fromMap(extensions);
            return this;
        }

        Builder allowedCredentials(@Nullable List<PublicKeyCredentialDescriptor> allowedCredentials) {
            this.allowedCredentials = allowedCredentials;
            return this;
        }

        PublicKeyCredential create() throws IOException, CommandException, ClientError {
            PublicKeyCredentialCreationOptions options = getCreateOptions(
                    new PublicKeyCredentialUserEntity(
                            "user",
                            "user".getBytes(StandardCharsets.UTF_8),
                            "User"
                    ),
                    residentKey,
                    Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                    extensions
            );
            return client.makeCredential(
                    TestData.CLIENT_DATA_JSON_CREATE,
                    options,
                    TestData.RP_ID,
                    TestData.PIN,
                    null,
                    null
            );
        }

        PublicKeyCredential getAssertions() throws IOException, CommandException, ClientError, MultipleAssertionsAvailable {
            PublicKeyCredentialRequestOptions requestOptions = new PublicKeyCredentialRequestOptions(
                    TestData.CHALLENGE,
                    (long) 90000,
                    TestData.RP_ID,
                    allowedCredentials,
                    null,
                    extensions
            );
            return client.getAssertion(
                    TestData.CLIENT_DATA_JSON_GET,
                    requestOptions,
                    TestData.RP_ID,
                    TestData.PIN,
                    null
            );
        }
    }

    @SuppressWarnings("unchecked")
    @Nullable
    private static Map<String, ?> getResult(Extension.ExtensionResults results, String name) {
        Assert.assertNotNull(results);
        Map<String, Object> resultsMap = results.toMap(SerializationType.JSON);
        return (Map<String, ?>) resultsMap.get(name);
    }

    private static PublicKeyCredentialCreationOptions getCreateOptions(
            @Nullable PublicKeyCredentialUserEntity user,
            boolean rk,
            List<PublicKeyCredentialParameters> credParams,
            @Nullable Extensions extensions
    ) {
        if (user == null) {
            user = TestData.USER;
        }
        PublicKeyCredentialRpEntity rp = TestData.RP;
        AuthenticatorSelectionCriteria criteria = new AuthenticatorSelectionCriteria(
                null,
                rk ? ResidentKeyRequirement.REQUIRED : ResidentKeyRequirement.DISCOURAGED,
                null
        );
        return new PublicKeyCredentialCreationOptions(
                rp,
                user,
                TestData.CHALLENGE,
                credParams,
                (long) 90000,
                null,
                criteria,
                null,
                extensions
        );
    }

    private static void deleteCredentials(
            @Nonnull BasicWebAuthnClient webAuthnClient,
            @Nonnull List<byte[]> credIds
    ) throws IOException, CommandException, ClientError {
        try {
            CredentialManager credentialManager = webAuthnClient.getCredentialManager(TestData.PIN);
            for (byte[] credId : credIds) {
                credentialManager.deleteCredential(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PUBLIC_KEY,
                                credId,
                                null));
            }
        } catch (IllegalStateException ignored) {
            // credential manager might not be supported
        }
    }
}
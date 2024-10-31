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

import com.squareup.moshi.JsonReader;
import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.Cose;
import com.yubico.yubikit.fido.webauthn.Extension;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import com.yubico.yubikit.testing.fido.utils.RequestOptionsBuilder;

import org.junit.Assert;
import org.junit.Assume;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

import okio.Buffer;

public class ExtSignTests {

    private final String SIGN_EXT = "sign";

    public static void testWithDiscoverableCredential(FidoTestState state) throws Throwable {
        ExtSignTests extTests = new ExtSignTests();
        extTests.runTest(state, true);
    }

    public static void testWithNonDiscoverableCredential(FidoTestState state) throws Throwable {
        ExtSignTests extTests = new ExtSignTests();
        extTests.runTest(state, false);
    }

    // this test is active only on devices without sign extension
    public static void testNoExtensionSupport(FidoTestState state) throws Throwable {
        ExtSignTests extTests = new ExtSignTests();
        extTests.runNoSupportTest(state);
    }

    private ExtSignTests() {

    }

    @SuppressWarnings("unchecked")
    private void runTest(FidoTestState state, boolean residentKey) throws Throwable {
        {
            List<PublicKeyCredential> credsToDelete = new ArrayList<>();

            // no output when no input
            state.withCtap2(session -> {
                Assume.assumeTrue(session.getCachedInfo().getExtensions().contains(SIGN_EXT));
                PublicKeyCredential cred = new ClientHelper(session).makeCredential(
                        new CreationOptionsBuilder()
                                .residentKey(residentKey)
                                .build()
                );
                Assert.assertNull(getSignResult(cred));
                credsToDelete.add(cred);
            });

            // create credential
            state.withCtap2(session -> {
                PublicKeyCredential cred = new ClientHelper(session).makeCredential(
                        new CreationOptionsBuilder()
                                .residentKey(residentKey)
                                .extensions(JsonUtils.fromJson("{\"sign\": {" +
                                        "    \"generateKey\": {" +
                                        "      \"algorithms\": [" +
                                        "        -7" +
                                        "      ]" +
                                        "    }" +
                                        "  }}"))
                                .build()
                );

                Map<String, Object> signCreateResult = getSignResult(cred);
                Assert.assertNotNull(signCreateResult);
                Assert.assertFalse(signCreateResult.containsKey("signature"));
                Map<String, Object> generatedKey = (Map<String, Object>) signCreateResult.get("generatedKey");
                Assert.assertNotNull(generatedKey);
                Assert.assertTrue(generatedKey.containsKey("publicKey"));
                Assert.assertTrue(generatedKey.containsKey("keyHandle"));
                credsToDelete.add(cred);
            });

            // sign on creation
            TestData testData = state.withCtap2(session -> {
                String testMessage = "Test message";
                String phData = Base64.toUrlSafeString(MessageDigest
                        .getInstance("SHA-256")
                        .digest(testMessage.getBytes(StandardCharsets.UTF_8)));
                PublicKeyCredential cred = new ClientHelper(session).makeCredential(
                        new CreationOptionsBuilder()
                                .residentKey(residentKey)
                                .extensions(JsonUtils.fromJson("{" +
                                        "      \"sign\": {" +
                                        "        \"generateKey\": {" +
                                        "          \"algorithms\": [" +
                                        "            -7" +
                                        "          ]," +
                                        "          \"phData\": \"" + phData + "\"" +
                                        "        }" +
                                        "      }" +
                                        "    }"))
                                .build()
                );

                Map<String, Object> signCreateResult = getSignResult(cred);
                Assert.assertNotNull(signCreateResult);
                Map<String, Object> generatedKey = (Map<String, Object>) signCreateResult.get("generatedKey");
                Assert.assertNotNull(generatedKey);

                String signature = (String) signCreateResult.get("signature");
                String publicKey = (String) generatedKey.get("publicKey");
                String keyHandle = (String) generatedKey.get("keyHandle");

                Assert.assertNotNull(signature);
                Assert.assertNotNull(publicKey);
                Assert.assertNotNull(keyHandle);

                verifySignature(publicKey, testMessage, signature);

                credsToDelete.add(cred);

                return new TestData(cred, publicKey, keyHandle);
            });

            // sign data
            state.withCtap2(session -> {
                String testMessage = "Test message";
                String phData = Base64.toUrlSafeString(MessageDigest
                        .getInstance("SHA-256")
                        .digest(testMessage.getBytes(StandardCharsets.UTF_8)));

                String credentialId = testData.publicKeyCredential.getId();
                String keyHandle = testData.signKeyHandle;

                PublicKeyCredential cred = new ClientHelper(session).getAssertions(
                        new RequestOptionsBuilder()
                                .allowedCredentials(testData.publicKeyCredential)
                                .extensions(JsonUtils.fromJson("{" +
                                        "  \"sign\": {" +
                                        "    \"sign\": {" +
                                        "      \"phData\": \"" + phData + "\"," +
                                        "      \"keyHandleByCredential\": {" +
                                        "          \"" + credentialId + "\":\"" + keyHandle + "\"" +
                                        "       }" +
                                        "    }" +
                                        "  }" +
                                        "}"))
                                .build()
                );

                Map<String, Object> signExtensionResult = getSignResult(cred);
                Assert.assertNotNull(signExtensionResult);
                Assert.assertTrue(signExtensionResult.containsKey("signature"));
                Assert.assertFalse(signExtensionResult.containsKey("generatedKey"));
                String signature = (String) signExtensionResult.get("signature");
                Assert.assertNotNull(signature);

                // verify sig
                verifySignature(testData.signPublicKey, testMessage, signature);
            });

            if (residentKey) {
                state.withCtap2(session -> {
                    // TODO verify with a test device
                    //  new ClientHelper(session).deleteCredentials(credsToDelete);
                });
            }
        }
    }

    private void runNoSupportTest(FidoTestState state) throws Throwable {
        state.withCtap2(session -> {
            Assume.assumeFalse(session.getCachedInfo().getExtensions().contains(SIGN_EXT));
            PublicKeyCredential cred = new ClientHelper(session)
                    .makeCredential(
                            new CreationOptionsBuilder()
                                    .extensions(Collections.singletonMap(SIGN_EXT, Collections.emptyMap()))
                                    .build()
                    );

            Assert.assertNull(getSignResult(cred));
        });
    }

    @SuppressWarnings("unchecked")
    @Nullable
    private Map<String, Object> getSignResult(PublicKeyCredential credential) {
        Extension.ExtensionResults results = credential.getClientExtensionResults();
        Assert.assertNotNull(results);
        Map<String, Object> resultsMap = results.toMap();
        return (Map<String, Object>) resultsMap.get(SIGN_EXT);
    }

    // helper class which holds create data
    static class TestData {
        final PublicKeyCredential publicKeyCredential;
        final String signPublicKey;
        final String signKeyHandle;


        TestData(PublicKeyCredential publicKeyCredential, String signPublicKey, String signKeyHandle) {
            this.publicKeyCredential = publicKeyCredential;
            this.signPublicKey = signPublicKey;
            this.signKeyHandle = signKeyHandle;
        }
    }

    @SuppressWarnings("unchecked")
    private void verifySignature(String b64CosePublicKey, String plainText, String b64Signature)
            throws InvalidKeySpecException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {

        Map<Integer, Object> coseKey = (Map<Integer, Object>) Cbor.decode(
                Base64.fromUrlSafeString(b64CosePublicKey)
        );

        Assert.assertNotNull(coseKey);
        PublicKey publicKey = Cose.getPublicKey(coseKey);

        Assert.assertEquals("Only ES256 is currently supported", -7, coseKey.get(3));
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(plainText.getBytes(StandardCharsets.UTF_8));
        Assert.assertTrue(verifier.verify(Base64.fromUrlSafeString(b64Signature)));
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

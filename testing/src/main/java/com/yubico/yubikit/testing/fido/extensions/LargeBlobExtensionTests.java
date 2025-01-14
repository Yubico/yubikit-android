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
import com.yubico.yubikit.testing.Codec;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import com.yubico.yubikit.testing.fido.utils.RequestOptionsBuilder;
import java.util.Collections;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Assert;
import org.junit.Assume;

public class LargeBlobExtensionTests {

  private static final String LARGE_BLOB = "largeBlob";
  private static final String LARGE_BLOB_KEY = "largeBlobKey";
  private static final String KEY_SUPPORT = "support";
  private static final String KEY_SUPPORTED = "supported";
  private static final String KEY_READ = "read";
  private static final String KEY_WRITE = "write";
  private static final String KEY_BLOB = "blob";
  private static final String KEY_WRITTEN = "written";
  private static final String ATTR_PREFERRED = "preferred";
  private static final String ATTR_REQUIRED = "required";

  public static void test(FidoTestState state) throws Throwable {
    LargeBlobExtensionTests largeBlobExtensionTests = new LargeBlobExtensionTests();
    largeBlobExtensionTests.runTest(state);
  }

  private LargeBlobExtensionTests() {}

  private void runTest(FidoTestState state) throws Throwable {
    final byte[] data1 = Codec.fromHex("112211221122112211221122112211");
    final byte[] data2 = Codec.fromHex("990099009900990099009900990099");

    // no output when no input
    state.withCtap2(
        session -> {
          Assume.assumeTrue(session.getCachedInfo().getExtensions().contains(LARGE_BLOB_KEY));
          PublicKeyCredential cred = new ClientHelper(session).makeCredential();
          Map<String, ?> result = getResult(cred);
          Assert.assertNull(result);
        });

    state.withCtap2(
        session -> {
          ClientHelper client = new ClientHelper(session);
          PublicKeyCredential cred =
              client.makeCredential(
                  new CreationOptionsBuilder()
                      .residentKey(true)
                      .extensions(
                          Collections.singletonMap(
                              LARGE_BLOB, Collections.singletonMap(KEY_SUPPORT, ATTR_PREFERRED)))
                      .build());

          Assert.assertEquals(Boolean.TRUE, getResultValue(cred, KEY_SUPPORTED));
          client.deleteCredentials(cred);
        });

    // read and write to different credentials and verify the contents is correct
    PublicKeyCredential cred1 = makeCred(state, "User1", Codec.fromHex("010101"));
    PublicKeyCredential cred2 = makeCred(state, "User2", Codec.fromHex("020202"));

    Assert.assertEquals(0, readBlob(state, cred1).length);
    Assert.assertEquals(0, readBlob(state, cred2).length);

    Assert.assertTrue(writeBlob(state, data1, cred1));
    Assert.assertArrayEquals(data1, readBlob(state, cred1));

    Assert.assertEquals(0, readBlob(state, cred2).length);

    Assert.assertTrue(writeBlob(state, data2, cred1));
    Assert.assertArrayEquals(data2, readBlob(state, cred1));

    Assert.assertEquals(0, readBlob(state, cred2).length);

    Assert.assertTrue(writeBlob(state, data1, cred2));
    Assert.assertArrayEquals(data1, readBlob(state, cred2));
    Assert.assertArrayEquals(data2, readBlob(state, cred1));

    deleteCreds(state, cred1, cred2);
  }

  private byte[] readBlob(FidoTestState state, @Nullable PublicKeyCredential allowedCredential)
      throws Throwable {
    return state.withCtap2(
        session -> {
          PublicKeyCredential cred =
              new ClientHelper(session)
                  .getAssertions(
                      new RequestOptionsBuilder()
                          .allowedCredentials(allowedCredential)
                          .extensions(
                              Collections.singletonMap(
                                  LARGE_BLOB, Collections.singletonMap(KEY_READ, true)))
                          .build());

          Map<String, ?> result = getResult(cred);
          Assert.assertNotNull(result); // nothing has been written yet
          if (result.isEmpty()) {
            return new byte[0];
          } else {
            Assert.assertNull(getResultValue(cred, KEY_WRITTEN));
            byte[] data = getBlob(cred);
            Assert.assertNotNull(data);
            return data;
          }
        });
  }

  private boolean writeBlob(
      FidoTestState state, byte[] data, @Nullable PublicKeyCredential allowedCredential)
      throws Throwable {
    return state.withCtap2(
        session -> {
          PublicKeyCredential cred =
              new ClientHelper(session)
                  .getAssertions(
                      new RequestOptionsBuilder()
                          .allowedCredentials(allowedCredential)
                          .extensions(
                              Collections.singletonMap(
                                  LARGE_BLOB,
                                  Collections.singletonMap(
                                      KEY_WRITE, Base64.toUrlSafeString(data))))
                          .build());

          Assert.assertNull(getResultValue(cred, KEY_BLOB));
          Boolean writtenValue = (Boolean) getResultValue(cred, KEY_WRITTEN);
          Assert.assertEquals(Boolean.TRUE, writtenValue);
          return writtenValue;
        });
  }

  private PublicKeyCredential makeCred(FidoTestState state, String name, byte[] id)
      throws Throwable {
    return state.withCtap2(
        session -> {
          PublicKeyCredential cred =
              new ClientHelper(session)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .userEntity(name, id)
                          .residentKey(true)
                          .extensions(
                              Collections.singletonMap(
                                  LARGE_BLOB, Collections.singletonMap(KEY_SUPPORT, ATTR_REQUIRED)))
                          .build());
          Assert.assertEquals(Boolean.TRUE, getResultValue(cred, KEY_SUPPORTED));
          return cred;
        });
  }

  private void deleteCreds(FidoTestState state, PublicKeyCredential... creds) throws Throwable {
    state.withCtap2(
        session -> {
          ClientHelper client = new ClientHelper(session);
          client.deleteCredentials(creds);
        });
  }

  @Nullable
  private Object getResultValue(PublicKeyCredential credential, String key) {
    Map<String, ?> largeBlob = getResult(credential);
    Assert.assertNotNull(largeBlob);
    return largeBlob.get(key);
  }

  @Nullable
  private byte[] getBlob(PublicKeyCredential credential) {
    Map<String, ?> largeBlob = getResult(credential, SerializationType.CBOR);
    Assert.assertNotNull(largeBlob);
    return (byte[]) largeBlob.get(KEY_BLOB);
  }

  @SuppressWarnings("unchecked")
  @Nullable
  private Map<String, ?> getResult(PublicKeyCredential cred, SerializationType serializationType) {
    ClientExtensionResults results = cred.getClientExtensionResults();
    ;
    Assert.assertNotNull(results);
    Map<String, Object> resultsMap = results.toMap(serializationType);
    return (Map<String, ?>) resultsMap.get(LARGE_BLOB);
  }

  @SuppressWarnings("unchecked")
  @Nullable
  private Map<String, ?> getResult(PublicKeyCredential cred) {
    ClientExtensionResults results = cred.getClientExtensionResults();
    ;
    Assert.assertNotNull(results);
    Map<String, Object> resultsMap = results.toMap(SerializationType.JSON);
    return (Map<String, ?>) resultsMap.get(LARGE_BLOB);
  }
}

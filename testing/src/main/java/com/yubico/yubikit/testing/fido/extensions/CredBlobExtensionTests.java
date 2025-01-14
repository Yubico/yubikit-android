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
import com.yubico.yubikit.fido.webauthn.AuthenticatorAssertionResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorData;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import com.yubico.yubikit.testing.fido.utils.RequestOptionsBuilder;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Assert;
import org.junit.Assume;

public class CredBlobExtensionTests {

  private static final String CRED_BLOB = "credBlob";
  private static final String GET_CRED_BLOB = "getCredBlob";
  private static final byte[] CRED_BLOB_DATA = {
    (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
    (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x02,
    (byte) 0x03, (byte) 0x03, (byte) 0x03, (byte) 0x03,
    (byte) 0x04, (byte) 0x04, (byte) 0x04, (byte) 0x04,
    (byte) 0x05, (byte) 0x05, (byte) 0x05, (byte) 0x05,
    (byte) 0x06, (byte) 0x06, (byte) 0x06, (byte) 0x06,
    (byte) 0x07, (byte) 0x07, (byte) 0x07, (byte) 0x07,
    (byte) 0x08, (byte) 0x08, (byte) 0x08, (byte) 0x08,
  };

  public static void test(FidoTestState state) throws Throwable {
    CredBlobExtensionTests extTest = new CredBlobExtensionTests();
    extTest.runTest(state);
  }

  private CredBlobExtensionTests() {}

  private void runTest(FidoTestState state) throws Throwable {
    // no output if extension not requestedΩ
    state.withCtap2(
        session -> {
          Assume.assumeTrue(
              "credBlob not supported",
              session.getCachedInfo().getExtensions().contains(CRED_BLOB));
          PublicKeyCredential cred = new ClientHelper(session).makeCredential();
          Assert.assertNull(getAttestationResult(cred));
        });

    // try to create with data > maxCredBlobLength
    state.withCtap2(
        session -> {
          ClientHelper client = new ClientHelper(session);
          int maxCredBlobLength = session.getCachedInfo().getMaxCredBlobLength();
          byte[] data = new byte[maxCredBlobLength + 1];
          Arrays.fill(data, (byte) 0x01);

          PublicKeyCredential cred =
              client.makeCredential(
                  new CreationOptionsBuilder()
                      .residentKey(true)
                      .extensions(Collections.singletonMap(CRED_BLOB, Base64.toUrlSafeString(data)))
                      .build());

          Object result = getAttestationResult(cred);
          client.deleteCredentials(cred);
          Assert.assertNull(result);
        });

    // store value
    PublicKeyCredential publicKeyCredential =
        state.withCtap2(
            session -> {
              PublicKeyCredential cred =
                  new ClientHelper(session)
                      .makeCredential(
                          new CreationOptionsBuilder()
                              .residentKey(true)
                              .extensions(
                                  Collections.singletonMap(
                                      CRED_BLOB, Base64.toUrlSafeString(CRED_BLOB_DATA)))
                              .build());
              Assert.assertEquals(Boolean.TRUE, getAttestationResult(cred));
              return cred;
            });

    // no value when extension not requested
    state.withCtap2(
        session -> {
          PublicKeyCredential cred =
              new ClientHelper(session)
                  .getAssertions(
                      new RequestOptionsBuilder().allowedCredentials(publicKeyCredential).build());
          Assert.assertNull(getAssertionResult(cred));
        });

    // no value when extension not explicitly refused
    state.withCtap2(
        session -> {
          PublicKeyCredential cred =
              new ClientHelper(session)
                  .getAssertions(
                      new RequestOptionsBuilder()
                          .allowedCredentials(publicKeyCredential)
                          .extensions(Collections.singletonMap(GET_CRED_BLOB, false))
                          .build());
          Assert.assertNull(getAssertionResult(cred));
        });

    // read value
    state.withCtap2(
        session -> {
          ClientHelper client = new ClientHelper(session);
          PublicKeyCredential cred =
              client.getAssertions(
                  new RequestOptionsBuilder()
                      .allowedCredentials(publicKeyCredential)
                      .extensions(Collections.singletonMap(GET_CRED_BLOB, true))
                      .build());
          Assert.assertArrayEquals(CRED_BLOB_DATA, getAssertionResult(cred));
          client.deleteCredentials(publicKeyCredential);
        });
  }

  @Nullable
  private Boolean getAttestationResult(PublicKeyCredential cred) {
    AuthenticatorAttestationResponse response =
        (AuthenticatorAttestationResponse) cred.getResponse();
    Map<String, ?> extensions = response.getAuthenticatorData().getExtensions();
    return extensions != null ? (Boolean) extensions.get(CRED_BLOB) : null;
  }

  @Nullable
  private byte[] getAssertionResult(PublicKeyCredential cred) {
    AuthenticatorAssertionResponse response = (AuthenticatorAssertionResponse) cred.getResponse();
    AuthenticatorData authenticatorData =
        AuthenticatorData.parseFrom(ByteBuffer.wrap(response.getAuthenticatorData()));
    Map<String, ?> extensions = authenticatorData.getExtensions();
    return extensions != null ? (byte[]) extensions.get(CRED_BLOB) : null;
  }
}

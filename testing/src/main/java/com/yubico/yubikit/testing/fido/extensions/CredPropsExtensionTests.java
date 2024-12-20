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
import java.util.Collections;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Assert;

public class CredPropsExtensionTests {

  private static final String CRED_PROPS = "credProps";

  public static void test(FidoTestState state) throws Throwable {
    CredPropsExtensionTests extTest = new CredPropsExtensionTests();
    extTest.runTest(state);
  }

  private CredPropsExtensionTests() {}

  private void runTest(FidoTestState state) throws Throwable {
    // no output in results if extension not requested
    state.withCtap2(
        session -> {
          PublicKeyCredential cred = new ClientHelper(session).makeCredential();
          Assert.assertNull(getResult(cred));
        });

    // rk value is correct (false) during registration
    state.withCtap2(
        session -> {
          PublicKeyCredential cred =
              new ClientHelper(session)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .residentKey(false)
                          .extensions(Collections.singletonMap(CRED_PROPS, true))
                          .build());

          Assert.assertEquals(Boolean.FALSE, getRkValue(cred));
        });

    // rk value is correct (true) during registration
    state.withCtap2(
        session -> {
          ClientHelper client = new ClientHelper(session);
          PublicKeyCredential cred =
              client.makeCredential(
                  new CreationOptionsBuilder()
                      .residentKey(true)
                      .extensions(Collections.singletonMap(CRED_PROPS, true))
                      .build());

          Assert.assertEquals(Boolean.TRUE, getRkValue(cred));
          client.deleteCredentials(cred);
        });
  }

  @SuppressWarnings("unchecked")
  @Nullable
  private Map<String, ?> getResult(PublicKeyCredential credential) {
    ClientExtensionResults results = credential.getClientExtensionResults();
    Assert.assertNotNull(results);
    Map<String, Object> resultsMap = results.toMap(SerializationType.JSON);
    return (Map<String, ?>) resultsMap.get(CRED_PROPS);
  }

  @Nullable
  private Object getRkValue(PublicKeyCredential credential) {
    Map<String, ?> credProps = getResult(credential);
    Assert.assertNotNull(credProps);
    return credProps.get("rk");
  }
}

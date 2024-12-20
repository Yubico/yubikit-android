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

import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import java.util.Collections;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Assert;
import org.junit.Assume;

public class CredProtectExtensionTests {

  private static final String CRED_PROTECT = "credProtect";
  private static final String POLICY = "credentialProtectionPolicy";
  private static final String POLICY_OPTIONAL = "userVerificationOptional";
  private static final String POLICY_WITH_LIST = "userVerificationOptionalWithCredentialIDList";
  private static final String POLICY_REQUIRED = "userVerificationRequired";

  public static void test(FidoTestState state) throws Throwable {
    CredProtectExtensionTests extTest = new CredProtectExtensionTests();
    extTest.runTest(state);
  }

  private CredProtectExtensionTests() {}

  private void runTest(FidoTestState state) throws Throwable {

    state.withCtap2(
        session -> {
          Assume.assumeTrue(
              "credProtect not supported",
              session.getCachedInfo().getExtensions().contains(CRED_PROTECT));
          PublicKeyCredential cred = new ClientHelper(session).makeCredential();
          Assert.assertNull(getCredProtectResult(cred));
        });

    state.withCtap2(
        session -> {
          PublicKeyCredential cred =
              new ClientHelper(session)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .extensions(Collections.singletonMap(POLICY, POLICY_OPTIONAL))
                          .build());

          Integer credProtect = getCredProtectResult(cred);
          Assert.assertNotNull(credProtect);
          Assert.assertEquals(0x01, credProtect.intValue());
        });

    state.withCtap2(
        session -> {
          PublicKeyCredential cred =
              new ClientHelper(session)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .extensions(Collections.singletonMap(POLICY, POLICY_WITH_LIST))
                          .build());

          Integer credProtect = getCredProtectResult(cred);
          Assert.assertNotNull(credProtect);
          Assert.assertEquals(0x02, credProtect.intValue());
        });

    state.withCtap2(
        session -> {
          ClientHelper client = new ClientHelper(session);
          PublicKeyCredential cred =
              client.makeCredential(
                  new CreationOptionsBuilder()
                      .residentKey(true)
                      .extensions(Collections.singletonMap(POLICY, POLICY_REQUIRED))
                      .build());

          Integer credProtect = getCredProtectResult(cred);
          Assert.assertNotNull(credProtect);
          Assert.assertEquals(0x03, credProtect.intValue());
          client.deleteCredentials(cred);
        });
  }

  @Nullable
  private Integer getCredProtectResult(PublicKeyCredential cred) {
    AuthenticatorAttestationResponse response =
        (AuthenticatorAttestationResponse) cred.getResponse();
    Map<String, ?> extensions = response.getAuthenticatorData().getExtensions();
    return extensions != null ? (Integer) extensions.get(CRED_PROTECT) : null;
  }
}

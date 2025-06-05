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

import com.yubico.yubikit.fido.ctap.Config;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.ConfigHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import java.util.Collections;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Assert;
import org.junit.Assume;

public class MinPinLengthExtensionTests {
  private static final String MIN_PIN_LENGTH = "minPinLength";

  public static void test(FidoTestState state) throws Throwable {
    MinPinLengthExtensionTests extTest = new MinPinLengthExtensionTests();
    extTest.runTest(state);
  }

  private MinPinLengthExtensionTests() {}

  private void runTest(FidoTestState state) throws Throwable {

    state.withCtap2(
        session -> {
          Assume.assumeTrue(
              "minPinLength not supported",
              session.getCachedInfo().getExtensions().contains(MIN_PIN_LENGTH));
          PublicKeyCredential cred = new ClientHelper(session).makeCredential();
          Assert.assertNull(getMinPinLength(cred));
        });

    state.withCtap2(
        session -> {
          // setup the authenticator to contain incorrect minPinLengthRPIDs
          Config config = ConfigHelper.getConfig(session, state);
          config.setMinPinLength(null, Collections.singletonList("wrongrpid.com"), null);

          PublicKeyCredential cred =
              new ClientHelper(session)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .extensions(Collections.singletonMap(MIN_PIN_LENGTH, true))
                          .build());

          Integer minPinLength = getMinPinLength(cred);
          Assert.assertNull(minPinLength);
        });

    state.withCtap2(
        session -> {
          // setup the authenticator to contain correct minPinLengthRPIDs
          Config config = ConfigHelper.getConfig(session, state);
          config.setMinPinLength(null, Collections.singletonList("example.com"), null);

          PublicKeyCredential cred =
              new ClientHelper(session)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .extensions(Collections.singletonMap(MIN_PIN_LENGTH, true))
                          .build());

          Integer optionsMinPinLength = session.getCachedInfo().getMinPinLength();
          Assert.assertNotNull(optionsMinPinLength);
          Integer minPinLength = getMinPinLength(cred);
          Assert.assertNotNull(minPinLength);
          Assert.assertEquals(optionsMinPinLength, minPinLength);
        });
  }

  @Nullable
  private Integer getMinPinLength(PublicKeyCredential cred) {
    AuthenticatorAttestationResponse response =
        (AuthenticatorAttestationResponse) cred.getResponse();
    Map<String, ?> extensions = response.getAuthenticatorData().getExtensions();
    return extensions != null ? (Integer) extensions.get(MIN_PIN_LENGTH) : null;
  }
}

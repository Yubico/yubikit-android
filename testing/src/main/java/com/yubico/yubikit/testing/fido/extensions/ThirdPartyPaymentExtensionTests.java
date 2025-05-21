/*
 * Copyright (C) 2025 Yubico.
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

import com.yubico.yubikit.fido.client.extensions.Extension;
import com.yubico.yubikit.fido.client.extensions.ThirdPartyPaymentExtension;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAssertionResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorData;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import com.yubico.yubikit.testing.fido.utils.RequestOptionsBuilder;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Assume;

public class ThirdPartyPaymentExtensionTests {
  private static final String THIRD_PARTY_PAYMENT = "thirdPartyPayment";
  private static final String PAYMENT = "payment";
  private static final String IS_PAYMENT = "isPayment";

  private static final List<Extension> extensions =
      Collections.singletonList(new ThirdPartyPaymentExtension());

  public static void test(FidoTestState state) throws Throwable {
    ThirdPartyPaymentExtensionTests extTest = new ThirdPartyPaymentExtensionTests();
    extTest.runTest(state, false);
    extTest.runTest(state, true);
  }

  private ThirdPartyPaymentExtensionTests() {}

  private void runTest(FidoTestState state, boolean rk) throws Throwable {

    {
      // create a new credential without the payment extension
      PublicKeyCredential publicKeyCredential =
          state.withCtap2(
              session -> {
                Assume.assumeTrue(
                    "thirdPartyPayment not supported",
                    session.getCachedInfo().getExtensions().contains(THIRD_PARTY_PAYMENT));
                return new ClientHelper(session, extensions)
                    .makeCredential(new CreationOptionsBuilder().residentKey(rk).build());
              });

      // check that the credential has the expected value
      // input:  { payment: { isPayment: true } }
      // authenticator extensions output: { thirdPartyPayment: false }
      state.withCtap2(
          session -> {
            RequestOptionsBuilder requestOptionsBuilder =
                new RequestOptionsBuilder()
                    .extensions(
                        Collections.singletonMap(
                            PAYMENT, Collections.singletonMap(IS_PAYMENT, true)));

            if (!rk) {
              requestOptionsBuilder.allowedCredentials(publicKeyCredential);
            }

            final ClientHelper client = new ClientHelper(session, extensions);
            PublicKeyCredential credential = client.getAssertions(requestOptionsBuilder.build());
            Assert.assertEquals(Boolean.FALSE, getThirdPartyPaymentValue(credential));

            if (rk) {
              client.deleteCredentials(publicKeyCredential);
            }
          });
    }

    // test with client input
    {
      // input:  { payment: { isPayment: true } }
      // output: {  }
      PublicKeyCredential publicKeyCredential =
          state.withCtap2(
              session -> {
                return new ClientHelper(session, extensions)
                    .makeCredential(
                        new CreationOptionsBuilder()
                            .residentKey(rk)
                            .extensions(
                                Collections.singletonMap(
                                    PAYMENT, Collections.singletonMap(IS_PAYMENT, true)))
                            .build());
              });

      // check that the credential has the expected value
      // input:  { payment: { isPayment: true } }
      // authenticator extensions output: { thirdPartyPayment: true }
      state.withCtap2(
          session -> {
            RequestOptionsBuilder requestOptionsBuilder =
                new RequestOptionsBuilder()
                    .extensions(
                        Collections.singletonMap(
                            PAYMENT, Collections.singletonMap(IS_PAYMENT, true)));

            if (!rk) {
              requestOptionsBuilder.allowedCredentials(publicKeyCredential);
            }

            final ClientHelper client = new ClientHelper(session, extensions);
            PublicKeyCredential credential = client.getAssertions(requestOptionsBuilder.build());
            Assert.assertEquals(Boolean.TRUE, getThirdPartyPaymentValue(credential));

            if (rk) {
              client.deleteCredentials(publicKeyCredential);
            }
          });
    }
  }

  // get the value of thirdPartyPayment extension from the authenticator data
  private static Boolean getThirdPartyPaymentValue(PublicKeyCredential credential) {
    AuthenticatorAssertionResponse response =
        (AuthenticatorAssertionResponse) credential.getResponse();

    AuthenticatorData authenticatorData =
        AuthenticatorData.parseFrom(ByteBuffer.wrap(response.getAuthenticatorData()));

    Map<String, ?> extensions = authenticatorData.getExtensions();
    Assert.assertNotNull("Extensions missing", extensions);
    return (Boolean) extensions.get(THIRD_PARTY_PAYMENT);
  }
}

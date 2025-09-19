/*
 * Copyright (C) 2020-2025 Yubico.
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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.client.BasicWebAuthnClient;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.client.CredentialManager;
import com.yubico.yubikit.fido.client.MultipleAssertionsAvailable;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAssertionResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import com.yubico.yubikit.fido.webauthn.UserVerificationRequirement;
import com.yubico.yubikit.testing.fido.utils.ClientHelper;
import com.yubico.yubikit.testing.fido.utils.CreationOptionsBuilder;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.Assert;

public class BasicWebAuthnClientTests {

  public static void testMakeCredentialGetAssertionTokenUvOnly(FidoTestState state)
      throws Throwable {
    state.withCtap2(
        session -> {
          assumeTrue("UV Token not supported", ClientPin.isTokenSupported(session.getCachedInfo()));
        });
    testMakeCredentialGetAssertion(state);
  }

  public static void testMakeCredentialGetAssertion(FidoTestState state) throws Throwable {
    List<byte[]> deleteCredIds = new ArrayList<>();

    // Make a non rk credential
    state.withCtap2(
        session -> {
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

          PublicKeyCredentialCreationOptions creationOptionsNonRk =
              getCreateOptions(
                  new PublicKeyCredentialUserEntity(
                      "user", "user".getBytes(StandardCharsets.UTF_8), "User"),
                  false,
                  Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                  null);
          PublicKeyCredential credNonRk =
              webauthn.makeCredential(
                  TestData.CLIENT_DATA_JSON_CREATE,
                  creationOptionsNonRk,
                  Objects.requireNonNull(creationOptionsNonRk.getRp().getId()),
                  TestData.PIN,
                  null,
                  null);
          AuthenticatorAttestationResponse responseNonRk =
              (AuthenticatorAttestationResponse) credNonRk.getResponse();
          assertNotNull("Failed to make non resident key credential", responseNonRk);
          assertNotNull(
              "Credential missing attestation object", responseNonRk.getAttestationObject());
          assertNotNull("Credential missing client data JSON", responseNonRk.getClientDataJson());
        });

    // make a rk credential
    state.withCtap2(
        session -> {
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
          PublicKeyCredentialCreationOptions creationOptionsRk =
              getCreateOptions(
                  new PublicKeyCredentialUserEntity(
                      "rkuser", "rkuser".getBytes(StandardCharsets.UTF_8), "RkUser"),
                  true,
                  Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                  null);
          PublicKeyCredential credRk =
              webauthn.makeCredential(
                  TestData.CLIENT_DATA_JSON_CREATE,
                  creationOptionsRk,
                  Objects.requireNonNull(creationOptionsRk.getRp().getId()),
                  TestData.PIN,
                  null,
                  null);
          AuthenticatorAttestationResponse responseRk =
              (AuthenticatorAttestationResponse) credRk.getResponse();
          assertNotNull("Failed to make resident key credential", responseRk);
          assertNotNull("Credential missing attestation object", responseRk.getAttestationObject());
          assertNotNull("Credential missing client data JSON", responseRk.getClientDataJson());
          deleteCredIds.add(
              (byte[])
                  parseCredentialData(getAuthenticatorDataFromAttestationResponse(responseRk))
                      .get("credId"));
        });

    // Get assertions
    state.withCtap2(
        session -> {
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
          PublicKeyCredentialRequestOptions requestOptions =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE, (long) 90000, TestData.RP_ID, null, null, null);

          try {
            PublicKeyCredential credential =
                webauthn.getAssertion(
                    TestData.CLIENT_DATA_JSON_GET,
                    requestOptions,
                    TestData.RP_ID,
                    TestData.PIN,
                    null);
            AuthenticatorAssertionResponse response =
                (AuthenticatorAssertionResponse) credential.getResponse();
            assertNotNull(
                "Assertion response missing authenticator data", response.getAuthenticatorData());
            assertNotNull("Assertion response missing signature", response.getSignature());
            assertNotNull("Assertion response missing user handle", response.getUserHandle());
          } catch (MultipleAssertionsAvailable multipleAssertionsAvailable) {
            fail("Got MultipleAssertionsAvailable even though there should only be one credential");
          }

          deleteCredentials(webauthn, deleteCredIds);
        });
  }

  public static void testCancelMakeCredential(FidoTestState state) throws Throwable {
    assumeTrue("Test only supported over USB transport", state.isUsbTransport());

    state.withCtap2(
        session -> {
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

          CommandState commandState = new CommandState();
          Executors.newSingleThreadScheduledExecutor()
              .schedule(commandState::cancel, 500, TimeUnit.MILLISECONDS);

          try {

            PublicKeyCredentialCreationOptions creationOptionsNonRk =
                getCreateOptions(
                    new PublicKeyCredentialUserEntity(
                        "user", "user".getBytes(StandardCharsets.UTF_8), "User"),
                    false,
                    Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                    null);
            webauthn.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE,
                creationOptionsNonRk,
                Objects.requireNonNull(creationOptionsNonRk.getRp().getId()),
                TestData.PIN,
                null,
                commandState);
            // cred should not be created because mc was cancelled
            fail("Failed to cancel");
          } catch (ClientError clientError) {
            assertEquals(ClientError.Code.TIMEOUT, clientError.getErrorCode());
          }
        });
  }

  public static void testUvDiscouragedMcGa_withPin(FidoTestState state) throws Throwable {
    state.withCtap2(
        session -> {
          assumeTrue(
              "Device has no PIN set",
              Boolean.TRUE.equals(session.getCachedInfo().getOptions().get("clientPin")));
        });
    testUvDiscouragedMakeCredentialGetAssertion(state);
  }

  public static void testUvDiscouragedMcGa_noPin(FidoTestState state) throws Throwable {
    state.withCtap2(
        session -> {
          assumeFalse(
              "Device has PIN set. Reset and try again.",
              Boolean.TRUE.equals(session.getCachedInfo().getOptions().get("clientPin")));
          assumeFalse("Ignoring FIPS approved devices", state.isFipsApproved());
        });
    testUvDiscouragedMakeCredentialGetAssertion(state);
  }

  private static void testUvDiscouragedMakeCredentialGetAssertion(FidoTestState state)
      throws Throwable {
    // Test non rk credential
    PublicKeyCredential credNonRk =
        state.withCtap2(
            session -> {
              BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

              PublicKeyCredentialCreationOptions creationOptionsNonRk =
                  getCreateOptions(
                      new PublicKeyCredentialUserEntity(
                          "user", "user".getBytes(StandardCharsets.UTF_8), "User"),
                      false,
                      Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                      null,
                      UserVerificationRequirement.DISCOURAGED);
              PublicKeyCredential publicKeyCredential =
                  webauthn.makeCredential(
                      TestData.CLIENT_DATA_JSON_CREATE,
                      creationOptionsNonRk,
                      Objects.requireNonNull(creationOptionsNonRk.getRp().getId()),
                      null,
                      null,
                      null);

              AuthenticatorAttestationResponse responseNonRk =
                  (AuthenticatorAttestationResponse) publicKeyCredential.getResponse();
              assertNotNull("Failed to make non resident key credential", responseNonRk);
              assertNotNull(
                  "Credential missing attestation object", responseNonRk.getAttestationObject());
              assertNotNull(
                  "Credential missing client data JSON", responseNonRk.getClientDataJson());
              return publicKeyCredential;
            });

    // Get assertions
    state.withCtap2(
        session -> {
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
          PublicKeyCredentialRequestOptions requestOptionsNonRk =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(credNonRk.getType(), credNonRk.getRawId())),
                  UserVerificationRequirement.DISCOURAGED,
                  null);

          try {
            PublicKeyCredential credential =
                webauthn.getAssertion(
                    TestData.CLIENT_DATA_JSON_GET, requestOptionsNonRk, TestData.RP_ID, null, null);
            AuthenticatorAssertionResponse response =
                (AuthenticatorAssertionResponse) credential.getResponse();
            assertNotNull(
                "Assertion response missing authenticator data", response.getAuthenticatorData());
            assertNotNull("Assertion response missing signature", response.getSignature());
            // User identifiable information (name, DisplayName, icon) MUST NOT be returned if user
            // verification is not done by the authenticator.
            assertNull("Assertion response contains user handle", response.getUserHandle());
          } catch (MultipleAssertionsAvailable multipleAssertionsAvailable) {
            fail("Got MultipleAssertionsAvailable even though there should only be one credential");
          }
        });

    // test rk credential
    PublicKeyCredential credRk =
        state.withCtap2(
            session -> {
              BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
              PublicKeyCredentialCreationOptions creationOptionsRk =
                  getCreateOptions(
                      new PublicKeyCredentialUserEntity(
                          "rkuser", "rkuser".getBytes(StandardCharsets.UTF_8), "RkUser"),
                      true,
                      Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                      null,
                      UserVerificationRequirement.DISCOURAGED);
              PublicKeyCredential publicKeyCredential =
                  webauthn.makeCredential(
                      TestData.CLIENT_DATA_JSON_CREATE,
                      creationOptionsRk,
                      Objects.requireNonNull(creationOptionsRk.getRp().getId()),
                      null,
                      null,
                      null);

              AuthenticatorAttestationResponse responseRk =
                  (AuthenticatorAttestationResponse) publicKeyCredential.getResponse();
              assertNotNull("Failed to make non resident key credential", responseRk);
              assertNotNull(
                  "Credential missing attestation object", responseRk.getAttestationObject());
              assertNotNull("Credential missing client data JSON", responseRk.getClientDataJson());
              return publicKeyCredential;
            });

    // Get assertions
    state.withCtap2(
        session -> {
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
          PublicKeyCredentialRequestOptions requestOptionsRk =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(credRk.getType(), credRk.getRawId())),
                  UserVerificationRequirement.DISCOURAGED,
                  null);

          try {
            PublicKeyCredential credential =
                webauthn.getAssertion(
                    TestData.CLIENT_DATA_JSON_GET, requestOptionsRk, TestData.RP_ID, null, null);
            AuthenticatorAssertionResponse response =
                (AuthenticatorAssertionResponse) credential.getResponse();
            assertNotNull(
                "Assertion response missing authenticator data", response.getAuthenticatorData());
            assertNotNull("Assertion response missing signature", response.getSignature());
            assertNotNull("Assertion response missing user handle", response.getUserHandle());
          } catch (MultipleAssertionsAvailable multipleAssertionsAvailable) {
            fail("Got MultipleAssertionsAvailable even though there should only be one credential");
          }
        });
  }

  public static void testGetAssertionMultipleUsersRk(FidoTestState state) throws Throwable {
    List<byte[]> deleteCredIds = new ArrayList<>();
    Map<byte[], byte[]> userIdCredIdMap = new HashMap<>();

    // make 3 rk credential
    for (int i = 0; i < 3; i++) {
      final int userIndex = i;
      state.withCtap2(
          session -> {
            BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
            PublicKeyCredentialUserEntity user =
                new PublicKeyCredentialUserEntity(
                    "user" + userIndex,
                    ("user" + userIndex).getBytes(StandardCharsets.UTF_8),
                    "User" + userIndex);
            PublicKeyCredentialCreationOptions creationOptions =
                getCreateOptions(
                    user,
                    true,
                    Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                    null);
            PublicKeyCredential credential =
                webauthn.makeCredential(
                    TestData.CLIENT_DATA_JSON_CREATE,
                    creationOptions,
                    Objects.requireNonNull(creationOptions.getRp().getId()),
                    TestData.PIN,
                    null,
                    null);
            AuthenticatorAttestationResponse response =
                (AuthenticatorAttestationResponse) credential.getResponse();
            byte[] credId =
                (byte[])
                    parseCredentialData(getAuthenticatorDataFromAttestationResponse(response))
                        .get("credId");
            userIdCredIdMap.put(user.getId(), credId);
            deleteCredIds.add(credId);
          });
    }

    // Get assertions
    PublicKeyCredentialRequestOptions requestOptions =
        new PublicKeyCredentialRequestOptions(
            TestData.CHALLENGE, (long) 90000, TestData.RP_ID, null, null, null);

    for (int i = 0; i < 3; i++) {
      final int userIndex = i;
      state.withCtap2(
          session -> {
            BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
            try {
              webauthn.getAssertion(
                  TestData.CLIENT_DATA_JSON_GET,
                  requestOptions,
                  TestData.RP_ID,
                  TestData.PIN,
                  null);
              fail("Got single assertion even though multiple credentials exist");
            } catch (MultipleAssertionsAvailable multipleAssertionsAvailable) {
              List<PublicKeyCredentialUserEntity> users = multipleAssertionsAvailable.getUsers();
              assertNotNull("Assertion failed to return user list", users);
              assertTrue("There should be at least 3 users found", users.size() >= 3);
              PublicKeyCredentialUserEntity user = users.get(userIndex);
              assertNotNull(user.getId());
              assertNotNull(user.getName());
              assertNotNull(user.getDisplayName());
              if (userIdCredIdMap.containsKey(user.getId())) {
                PublicKeyCredential credential = multipleAssertionsAvailable.select(userIndex);
                AuthenticatorAssertionResponse assertion =
                    (AuthenticatorAssertionResponse) credential.getResponse();
                assertNotNull("Failed to get assertion", assertion);
                assertNotNull(
                    "Assertion response missing authenticator data",
                    assertion.getAuthenticatorData());
                assertNotNull("Assertion response missing signature", assertion.getSignature());
                assertNotNull("Assertion response missing user handle", assertion.getUserHandle());
                assertArrayEquals(
                    userIdCredIdMap.get(users.get(userIndex).getId()), credential.getRawId());
              }
            }
          });
    }

    state.withCtap2(
        session -> {
          // GetAssertions with allowCreds containing non-existing credential
          List<PublicKeyCredentialDescriptor> allowCreds =
              Collections.singletonList(
                  new PublicKeyCredentialDescriptor(
                      PublicKeyCredentialType.PUBLIC_KEY, new byte[] {0}, null));
          PublicKeyCredentialRequestOptions options =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE, (long) 90000, TestData.RP_ID, allowCreds, null, null);

          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
          ClientError clientError =
              assertThrows(
                  ClientError.class,
                  () ->
                      webauthn.getAssertion(
                          TestData.CLIENT_DATA_JSON_GET,
                          options,
                          TestData.RP_ID,
                          TestData.PIN,
                          null));

          Throwable cause = clientError.getCause();
          assertThat(cause, instanceOf(CtapException.class));
          CtapException ctapException = (CtapException) cause;
          assertEquals(CtapException.ERR_NO_CREDENTIALS, ctapException.getCtapError());
        });

    state.withCtap2(
        session -> {
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
          if (CredentialManagement.isSupported(session.getCachedInfo())) {
            deleteCredentials(webauthn, deleteCredIds);
          }
        });
  }

  public static void testGetAssertionWithAllowList(FidoTestState state) throws Throwable {

    PublicKeyCredential cred1 =
        state.withCtap2(
            session -> {
              BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

              // Make 2 new credentials
              PublicKeyCredentialCreationOptions options =
                  getCreateOptions(
                      new PublicKeyCredentialUserEntity(
                          "user1", "user1".getBytes(StandardCharsets.UTF_8), "testUser1"),
                      false,
                      Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                      null);

              return webauthn.makeCredential(
                  TestData.CLIENT_DATA_JSON_CREATE,
                  options,
                  Objects.requireNonNull(TestData.RP.getId()),
                  TestData.PIN,
                  null,
                  null);
            });

    PublicKeyCredential cred2 =
        state.withCtap2(
            session -> {
              BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

              PublicKeyCredentialCreationOptions options =
                  getCreateOptions(
                      new PublicKeyCredentialUserEntity(
                          "user2", "user2".getBytes(StandardCharsets.UTF_8), "testUser2"),
                      false,
                      Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                      null);

              return webauthn.makeCredential(
                  TestData.CLIENT_DATA_JSON_CREATE,
                  options,
                  Objects.requireNonNull(TestData.RP.getId()),
                  TestData.PIN,
                  null,
                  null);
            });

    state.withCtap2(
        session -> {
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

          // GetAssertions with allowList containing only credId1
          List<PublicKeyCredentialDescriptor> allowCreds =
              Collections.singletonList(
                  new PublicKeyCredentialDescriptor(
                      PublicKeyCredentialType.PUBLIC_KEY, cred1.getRawId(), null));
          PublicKeyCredentialRequestOptions requestOptions =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE, (long) 90000, TestData.RP_ID, allowCreds, null, null);

          PublicKeyCredential credential =
              webauthn.getAssertion(
                  TestData.CLIENT_DATA_JSON_GET,
                  requestOptions,
                  TestData.RP_ID,
                  TestData.PIN,
                  null);
          assertArrayEquals(cred1.getRawId(), credential.getRawId());
        });

    state.withCtap2(
        session -> {
          // GetAssertions with allowList containing only credId2
          List<PublicKeyCredentialDescriptor> allowCreds =
              Collections.singletonList(
                  new PublicKeyCredentialDescriptor(
                      PublicKeyCredentialType.PUBLIC_KEY, cred2.getRawId(), null));
          PublicKeyCredentialRequestOptions requestOptions =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE, (long) 90000, TestData.RP_ID, allowCreds, null, null);

          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
          PublicKeyCredential credential =
              webauthn.getAssertion(
                  TestData.CLIENT_DATA_JSON_GET,
                  requestOptions,
                  TestData.RP_ID,
                  TestData.PIN,
                  null);
          assertArrayEquals(cred2.getRawId(), credential.getRawId());
        });
  }

  public static void testMakeCredentialWithExcludeList(FidoTestState state) throws Throwable {

    // non-discoverable
    {
      PublicKeyCredential cred =
          state.withCtap2(
              session -> {
                return new ClientHelper(session)
                    .makeCredential(new CreationOptionsBuilder().build());
              });

      // Make another non RK credential with exclude list including credId. Should fail
      state.withCtap2(
          session -> {
            try {
              new ClientHelper(session)
                  .makeCredential(new CreationOptionsBuilder().excludeCredentials(cred).build());
              fail("Succeeded in making credential even though the credential was excluded");
            } catch (ClientError clientError) {
              assertEquals(ClientError.Code.DEVICE_INELIGIBLE, clientError.getErrorCode());
            }
          });

      // Make another non RK credential with exclude list null. Should succeed
      state.withCtap2(
          session -> {
            return new ClientHelper(session).makeCredential(new CreationOptionsBuilder().build());
          });
    }

    // discoverable
    {
      List<PublicKeyCredential> creds = new ArrayList<>();
      for (int index = 0; index < 17; index++) {
        final int i = index;
        state.withCtap2(
            session -> {
              creds.add(
                  new ClientHelper(session)
                      .makeCredential(
                          new CreationOptionsBuilder()
                              .userEntity("User " + i)
                              .residentKey(true)
                              .build()));
            });
      }

      // Make another non RK credential with exclude list including credId. Should fail
      state.withCtap2(
          session -> {
            try {
              new ClientHelper(session)
                  .makeCredential(
                      new CreationOptionsBuilder()
                          .userEntity("Not allowed user")
                          .residentKey(true)
                          .excludeCredentials(creds)
                          .build());
              fail("Succeeded in making credential even though the credential was excluded");
            } catch (ClientError clientError) {
              assertEquals(ClientError.Code.DEVICE_INELIGIBLE, clientError.getErrorCode());
            }
          });

      // Make another non RK credential with exclude list null. Should succeed
      state.withCtap2(
          session -> {
            creds.add(
                new ClientHelper(session)
                    .makeCredential(
                        new CreationOptionsBuilder()
                            .userEntity("User3")
                            .residentKey(true)
                            .build()));
          });

      // remove credentials
      state.withCtap2(
          session -> {
            ClientHelper clientHelper = new ClientHelper(session);
            clientHelper.deleteCredentials(creds);
          });
    }
  }

  public static void testMakeCredentialKeyAlgorithms(FidoTestState state) throws Throwable {

    List<PublicKeyCredentialParameters> allCredParams =
        Arrays.asList(TestData.PUB_KEY_CRED_PARAMS_ES256, TestData.PUB_KEY_CRED_PARAMS_EDDSA);

    // Test individual algorithms
    for (PublicKeyCredentialParameters param : allCredParams) {
      state.withCtap2(
          session -> {
            BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

            PublicKeyCredentialCreationOptions creationOptions =
                getCreateOptions(null, false, Collections.singletonList(param), null);
            PublicKeyCredential credential =
                webauthn.makeCredential(
                    TestData.CLIENT_DATA_JSON_CREATE,
                    creationOptions,
                    Objects.requireNonNull(creationOptions.getRp().getId()),
                    TestData.PIN,
                    null,
                    null);
            AuthenticatorAttestationResponse attestation =
                (AuthenticatorAttestationResponse) credential.getResponse();
            int alg =
                (Integer)
                    Objects.requireNonNull(
                        parseCredentialData(
                                getAuthenticatorDataFromAttestationResponse(attestation))
                            .get("keyAlgo"));
            assertEquals(param.getAlg(), alg);
          });
    }

    state.withCtap2(
        session -> {
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
          // Test algorithm order: ES256 - EdDSA
          List<PublicKeyCredentialParameters> credParams =
              Arrays.asList(allCredParams.get(0), allCredParams.get(1));
          PublicKeyCredentialCreationOptions creationOptions =
              getCreateOptions(null, false, credParams, null);
          PublicKeyCredential credential =
              webauthn.makeCredential(
                  TestData.CLIENT_DATA_JSON_CREATE,
                  creationOptions,
                  Objects.requireNonNull(creationOptions.getRp().getId()),
                  TestData.PIN,
                  null,
                  null);
          AuthenticatorAttestationResponse attestation =
              (AuthenticatorAttestationResponse) credential.getResponse();
          int alg =
              (Integer)
                  Objects.requireNonNull(
                      parseCredentialData(getAuthenticatorDataFromAttestationResponse(attestation))
                          .get("keyAlgo"));
          assertEquals(credParams.get(0).getAlg(), alg);
        });

    state.withCtap2(
        session -> {
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
          // Test algorithm order: ALG_EdDSA - ALG_ES256
          List<PublicKeyCredentialParameters> credParams =
              Arrays.asList(allCredParams.get(1), allCredParams.get(0));
          PublicKeyCredentialCreationOptions creationOptions =
              getCreateOptions(null, false, credParams, null);
          PublicKeyCredential credential =
              webauthn.makeCredential(
                  TestData.CLIENT_DATA_JSON_CREATE,
                  creationOptions,
                  Objects.requireNonNull(creationOptions.getRp().getId()),
                  TestData.PIN,
                  null,
                  null);
          AuthenticatorAttestationResponse attestation =
              (AuthenticatorAttestationResponse) credential.getResponse();
          int alg =
              (Integer)
                  Objects.requireNonNull(
                      parseCredentialData(getAuthenticatorDataFromAttestationResponse(attestation))
                          .get("keyAlgo"));
          assertEquals(credParams.get(0).getAlg(), alg);
        });
  }

  public static void testClientPinManagement(FidoTestState state) throws Throwable {
    state.withCtap2(
        session -> {
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
          assumeTrue("Pin not supported", webauthn.isPinSupported());
          assertTrue(webauthn.isPinConfigured());

          webauthn.changePin(TestData.PIN, TestData.OTHER_PIN);

          try {
            webauthn.changePin(TestData.PIN, TestData.OTHER_PIN);
            fail("Wrong PIN was accepted");
          } catch (ClientError e) {
            assertThat(e.getErrorCode(), equalTo(ClientError.Code.BAD_REQUEST));
            assertThat(e.getCause(), instanceOf(CtapException.class));
            assertThat(
                ((CtapException) Objects.requireNonNull(e.getCause())).getCtapError(),
                is(CtapException.ERR_PIN_INVALID));
          }

          webauthn.changePin(TestData.OTHER_PIN, TestData.PIN);
        });
  }

  public static void testClientCredentialManagement(FidoTestState state) throws Throwable {
    state.withCtap2(
        session -> {
          assumeTrue(
              "Credential management not supported",
              CredentialManagement.isSupported(session.getCachedInfo()));
          BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
          PublicKeyCredentialCreationOptions creationOptions =
              getCreateOptions(
                  null, true, Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256), null);
          webauthn.makeCredential(
              TestData.CLIENT_DATA_JSON_CREATE,
              creationOptions,
              Objects.requireNonNull(creationOptions.getRp().getId()),
              TestData.PIN,
              null,
              null);

          CredentialManager credentialManager = webauthn.getCredentialManager(TestData.PIN);

          assertThat(credentialManager.getCredentialCount(), equalTo(1));

          List<String> rpIds = credentialManager.getRpIdList();
          assertThat(rpIds, equalTo(Collections.singletonList(TestData.RP_ID)));

          Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> credentials =
              credentialManager.getCredentials(TestData.RP_ID);
          assertThat(credentials.size(), equalTo(1));
          PublicKeyCredentialDescriptor key = credentials.entrySet().iterator().next().getKey();
          assertThat(
              Objects.requireNonNull(credentials.get(key)).getId(), equalTo(TestData.USER_ID));

          try {
            PublicKeyCredentialUserEntity updatedUser =
                new PublicKeyCredentialUserEntity(
                    "New name", credentials.get(key).getId(), "New display name");
            credentialManager.updateUserInformation(key, updatedUser);

            // verify new information
            Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> updatedCreds =
                credentialManager.getCredentials(TestData.RP_ID);
            assertThat(updatedCreds.size(), equalTo(1));
            PublicKeyCredentialDescriptor updatedKey = updatedCreds.keySet().iterator().next();
            PublicKeyCredentialUserEntity updatedUserEntity =
                Objects.requireNonNull(updatedCreds.get(updatedKey));
            assertThat(updatedUserEntity.getId(), equalTo(TestData.USER_ID));
            assertThat(updatedUserEntity.getName(), equalTo("New name"));
            assertThat(updatedUserEntity.getDisplayName(), equalTo("New display name"));
          } catch (UnsupportedOperationException unsupportedOperationException) {
            // ignored
          }

          credentialManager.deleteCredential(key);
          assertThat(credentialManager.getCredentialCount(), equalTo(0));
          assertTrue(credentialManager.getCredentials(TestData.RP_ID).isEmpty());
          assertTrue(credentialManager.getRpIdList().isEmpty());
        });
  }

  private static PublicKeyCredentialCreationOptions getCreateOptions(
      @Nullable PublicKeyCredentialUserEntity user,
      boolean rk,
      List<PublicKeyCredentialParameters> credParams,
      @Nullable List<PublicKeyCredentialDescriptor> excludeCredentials) {
    return getCreateOptions(user, rk, credParams, excludeCredentials, null);
  }

  private static PublicKeyCredentialCreationOptions getCreateOptions(
      @Nullable PublicKeyCredentialUserEntity user,
      boolean rk,
      List<PublicKeyCredentialParameters> credParams,
      @Nullable List<PublicKeyCredentialDescriptor> excludeCredentials,
      @Nullable String userVerification) {
    if (user == null) {
      user = TestData.USER;
    }
    PublicKeyCredentialRpEntity rp = TestData.RP;
    AuthenticatorSelectionCriteria criteria =
        new AuthenticatorSelectionCriteria(
            null,
            rk ? ResidentKeyRequirement.REQUIRED : ResidentKeyRequirement.DISCOURAGED,
            userVerification);
    return new PublicKeyCredentialCreationOptions(
        rp,
        user,
        TestData.CHALLENGE,
        credParams,
        (long) 90000,
        excludeCredentials,
        criteria,
        null,
        null);
  }

  private static byte[] getAuthenticatorDataFromAttestationResponse(
      AuthenticatorAttestationResponse response) {
    byte[] attestObjBytes = response.getAttestationObject();
    @SuppressWarnings("unchecked")
    Map<String, Object> attestObj = (Map<String, Object>) Cbor.decode(attestObjBytes);
    Assert.assertNotNull(attestObj);
    return (byte[]) attestObj.get("authData");
  }

  private static Map<String, Object> parseCredentialData(final byte[] data) {
    ByteBuffer bb = ByteBuffer.wrap(data);
    byte[] rpIdHash = new byte[32];
    bb.get(rpIdHash);

    byte flags = bb.get();

    int signCount = bb.getInt();

    byte[] aaguid = new byte[16];
    bb.get(aaguid);

    short idLength = bb.getShort();
    byte[] credId = new byte[idLength];
    bb.get(credId);

    byte[] key = new byte[bb.remaining()];
    bb.get(key);

    Map<String, Object> credData = new HashMap<>();
    credData.put("rpIdHash", rpIdHash);
    credData.put("flags", flags);
    credData.put("signCount", signCount);
    credData.put("aaguid", aaguid);
    credData.put("credId", credId);
    credData.put("pubkey", key);
    credData.put("keyAlgo", getAlgoFromCredentialPublicKey(key));
    return credData;
  }

  private static int getAlgoFromCredentialPublicKey(byte[] pubKey) {
    @SuppressWarnings("unchecked")
    Map<Integer, ?> credPublicKey = (Map<Integer, ?>) Cbor.decode(pubKey);
    Assert.assertNotNull(credPublicKey);
    return (Integer) Objects.requireNonNull(credPublicKey.get(3));
  }

  private static void deleteCredentials(
      @Nonnull BasicWebAuthnClient webAuthnClient, @Nonnull List<byte[]> credIds)
      throws IOException, CommandException, ClientError {
    CredentialManager credentialManager = webAuthnClient.getCredentialManager(TestData.PIN);
    for (byte[] credId : credIds) {
      credentialManager.deleteCredential(
          new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credId, null));
    }
  }
}

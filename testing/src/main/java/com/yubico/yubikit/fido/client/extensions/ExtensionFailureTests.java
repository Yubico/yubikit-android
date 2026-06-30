/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit.fido.client.extensions;

import static org.junit.Assert.assertThrows;

import com.yubico.yubikit.fido.FidoTestState;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.utils.ClientHelper;
import com.yubico.yubikit.fido.utils.CreationOptionsBuilder;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.Assert;

/**
 * Device tests for how the WebAuthn client handles extension processing failures.
 *
 * <p>These exercise the loop logic in {@code Ctap2Client} directly by injecting fake extensions, so
 * they do not depend on any particular authenticator capability:
 *
 * <ul>
 *   <li>an extension that fails in an ignorable way is skipped without aborting the ceremony or
 *       suppressing other extensions;
 *   <li>an extension that raises {@link ExtensionConfigurationException} aborts the ceremony with a
 *       {@link ClientError};
 *   <li>a relying-party misconfiguration ({@code largeBlob} read/write during registration) is
 *       reported as {@link ClientError.Code#BAD_REQUEST}.
 * </ul>
 */
public class ExtensionFailureTests {

  private static final String GOOD_RESULT_KEY = "testGoodResult";

  public static void test(FidoTestState state) throws Throwable {
    ExtensionFailureTests extTest = new ExtensionFailureTests();
    extTest.testIgnorableFailureDoesNotSuppressSiblings(state);
    extTest.testHardFailureAbortsWithClientError(state);
    extTest.testLargeBlobReadWriteInMakeCredentialIsBadRequest(state);
  }

  private ExtensionFailureTests() {}

  /** A failing extension must not prevent a sibling extension from producing its result. */
  private void testIgnorableFailureDoesNotSuppressSiblings(FidoTestState state) throws Throwable {
    state.withCtap2(
        session -> {
          ClientHelper client =
              new ClientHelper(
                  session, Arrays.asList(new IgnorableFailingExtension(), new GoodExtension()));

          PublicKeyCredential cred = client.makeCredential(new CreationOptionsBuilder().build());

          ClientExtensionResults results = cred.getClientExtensionResults();
          Assert.assertNotNull("Expected client extension results", results);
          Map<String, ?> resultMap = results.toMap(SerializationType.CBOR);
          Assert.assertEquals(
              "Sibling extension result was suppressed by a failing extension",
              Boolean.TRUE,
              resultMap.get(GOOD_RESULT_KEY));
        });
  }

  /** A hard-fail extension must abort the ceremony with the carried {@link ClientError.Code}. */
  private void testHardFailureAbortsWithClientError(FidoTestState state) throws Throwable {
    state.withCtap2(
        session -> {
          ClientHelper client =
              new ClientHelper(session, Collections.singletonList(new HardFailingExtension()));

          ClientError error =
              assertThrows(
                  ClientError.class,
                  () -> client.makeCredential(new CreationOptionsBuilder().build()));
          Assert.assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, error.getErrorCode());
        });
  }

  /** Requesting largeBlob read/write during registration is a malformed request. */
  private void testLargeBlobReadWriteInMakeCredentialIsBadRequest(FidoTestState state)
      throws Throwable {
    state.withCtap2(
        session -> {
          ClientHelper client = new ClientHelper(session);

          ClientError error =
              assertThrows(
                  ClientError.class,
                  () ->
                      client.makeCredential(
                          new CreationOptionsBuilder()
                              .extensions(
                                  Collections.singletonMap(
                                      "largeBlob", Collections.singletonMap("read", true)))
                              .build()));
          Assert.assertEquals(ClientError.Code.BAD_REQUEST, error.getErrorCode());
        });
  }

  /** Fails in an ignorable way during the build phase; the client should skip it. */
  private static class IgnorableFailingExtension extends Extension {
    IgnorableFailingExtension() {
      super("test-ignorable-failing");
    }

    @Nullable
    @Override
    public RegistrationProcessor makeCredential(
        @NonNull Ctap2Session ctap,
        @NonNull PublicKeyCredentialCreationOptions options,
        @NonNull PinUvAuthProtocol pinUvAuthProtocol) {
      throw new IllegalArgumentException("ignorable failure");
    }
  }

  /** Produces a client extension result but no authenticator input, so it is hardware-agnostic. */
  private static class GoodExtension extends Extension {
    GoodExtension() {
      super("test-good");
    }

    @Nullable
    @Override
    public RegistrationProcessor makeCredential(
        @NonNull Ctap2Session ctap,
        @NonNull PublicKeyCredentialCreationOptions options,
        @NonNull PinUvAuthProtocol pinUvAuthProtocol) {
      return new RegistrationProcessor(
          (attestationObject, pinToken) ->
              serializationType -> Collections.singletonMap(GOOD_RESULT_KEY, true));
    }
  }

  /** Signals a hard failure that must abort the ceremony. */
  private static class HardFailingExtension extends Extension {
    HardFailingExtension() {
      super("test-hard-failing");
    }

    @Nullable
    @Override
    public RegistrationProcessor makeCredential(
        @NonNull Ctap2Session ctap,
        @NonNull PublicKeyCredentialCreationOptions options,
        @NonNull PinUvAuthProtocol pinUvAuthProtocol) {
      throw new ExtensionConfigurationException(
          ClientError.Code.CONFIGURATION_UNSUPPORTED, "hard failure");
    }
  }
}

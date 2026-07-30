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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.fido.FidoTestState;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.client.Ctap2Client;
import com.yubico.yubikit.fido.ctap.Ctap1Session;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.utils.TestData;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Device tests for the appid and appidExclude WebAuthn extensions.
 *
 * <p>These tests register a credential via raw CTAP1 (U2F) commands so that the credential is bound
 * to SHA-256(LEGACY_APP_ID) rather than SHA-256(RP_ID). They then exercise the appid/appidExclude
 * extensions via a Ctap2Client to verify that the legacy credential is correctly recognized.
 *
 * <p>Requires a YubiKey that supports both U2F (CTAP1) and FIDO2 (CTAP2).
 *
 * @see <a href="https://w3c.github.io/webauthn/#sctn-appid-extension">appid extension</a>
 * @see <a href="https://w3c.github.io/webauthn/#sctn-appid-exclude-extension">appidExclude
 *     extension</a>
 */
public class AppIdExtensionTests {

  // The legacy U2F AppID — a full origin URL. In real life this would have been
  // what the browser passed to the U2F API.  Its SHA-256 is what the YubiKey
  // stores as the credential's "application parameter".
  //
  // TestData.RP_ID  = "example.com"
  // TestData.ORIGIN = "https://example.com"
  //
  // We intentionally use TestData.ORIGIN as the legacy AppID so that
  // SHA-256("https://example.com") ≠ SHA-256("example.com").
  private static final String LEGACY_APP_ID = TestData.ORIGIN; // "https://example.com"
  private static final String TEST_FACET_ID = "android:apk-key-hash:test-facet";
  private static final AppIdFacetVerifier ALLOW_TEST_FACET =
      (appId, facetId) -> TEST_FACET_ID.equals(facetId);

  private static Ctap2Client createClientWithFacet(Ctap2Session session, List<Extension> extensions)
      throws Exception {
    Ctap2Client client = new Ctap2Client(session, extensions);
    client.getUserAgentConfiguration().setAppIdFacetId(TEST_FACET_ID);
    client.getUserAgentConfiguration().setAppIdFacetVerifier(ALLOW_TEST_FACET);
    return client;
  }

  private static Ctap2Client createClientWithFacetVerifier(
      Ctap2Session session, List<Extension> extensions, AppIdFacetVerifier verifier)
      throws Exception {
    Ctap2Client client = new Ctap2Client(session, extensions);
    client.getUserAgentConfiguration().setAppIdFacetId(TEST_FACET_ID);
    client.getUserAgentConfiguration().setAppIdFacetVerifier(verifier);
    return client;
  }

  private static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  // ── Step 1: Register via raw CTAP1 ─────────────────────────────────────────

  /**
   * Registers a credential on the YubiKey using the raw CTAP1 (U2F) register command. The
   * credential is scoped to {@code SHA-256(LEGACY_APP_ID)}.
   *
   * <p>Returns the key handle (credential ID) that was created.
   */
  private static byte[] registerViaCtap1(Ctap1Session session) throws Exception {
    byte[] appParam = sha256(LEGACY_APP_ID.getBytes(StandardCharsets.UTF_8));
    byte[] clientParam = TestData.CLIENT_DATA_HASH;

    Ctap1Session.RegistrationData regData = session.register(clientParam, appParam);

    // Sanity-check: the attestation must verify against the appParam we sent.
    regData.verify(appParam, clientParam);

    byte[] keyHandle = regData.getKeyHandle();
    assertNotNull("Key handle must not be null", keyHandle);
    return keyHandle;
  }

  /**
   * Verifies the raw U2F credential can be authenticated with CTAP1 using the legacy appParam. This
   * is a basic prerequisite sanity check before we involve CTAP2 extensions.
   */
  private static void verifyCtap1Authentication(Ctap1Session session, byte[] keyHandle)
      throws Exception {
    byte[] appParam = sha256(LEGACY_APP_ID.getBytes(StandardCharsets.UTF_8));
    byte[] clientParam = TestData.CLIENT_DATA_HASH;

    Ctap1Session.SignatureData sigData =
        session.authenticate(clientParam, appParam, keyHandle, false);
    assertNotNull("Signature data must not be null", sigData);
    assertNotNull("Signature must not be null", sigData.getSignature());
  }

  // ── Step 2: appid extension — getAssertion ─────────────────────────────────

  /**
   * Tests that a legacy U2F credential can be used for authentication via CTAP2 when the {@code
   * appid} extension is supplied.
   *
   * <p>Flow:
   *
   * <ol>
   *   <li>Register via CTAP1 with {@code appParam = SHA-256("https://example.com")}.
   *   <li>Open a new CTAP2 session on the same key.
   *   <li>Call {@code getAssertion} with {@code rpId = "example.com"} and {@code extensions.appid =
   *       "https://example.com"}.
   *   <li>Assert that the assertion succeeds.
   * </ol>
   */
  public static void testAppIdGetAssertion(FidoTestState state) throws Throwable {

    // Register via CTAP1
    byte[] keyHandle = state.withCtap1(AppIdExtensionTests::registerViaCtap1);

    // Authenticate via CTAP2 with the appid extension
    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions =
              Collections.singletonList(
                  new AppIdExtension() // your implementation
                  );
          Ctap2Client client = createClientWithFacet(session, extensions);

          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appid", LEGACY_APP_ID);

          PublicKeyCredentialRequestOptions options =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, keyHandle)),
                  null, // userVerification
                  Extensions.fromMap(extMap));

          PublicKeyCredential assertion =
              client.getAssertion(
                  TestData.CLIENT_DATA_JSON_GET_PROVIDER,
                  options,
                  TestData.RP_ID,
                  TestData.PIN,
                  null);

          assertNotNull("Assertion must succeed with appid extension", assertion);
          assertNotNull("Assertion response must not be null", assertion.getResponse());
        });
  }

  /**
   * Negative test: without the appid extension the CTAP2 authenticator cannot find the U2F
   * credential because it only checks {@code SHA-256("example.com")} — not {@code
   * SHA-256("https://example.com")}.
   */
  public static void testGetAssertionFailsWithoutAppId(FidoTestState state) throws Throwable {

    byte[] keyHandle = state.withCtap1(AppIdExtensionTests::registerViaCtap1);

    state.withCtap2(
        (session, fidoState) -> {
          Ctap2Client client = new Ctap2Client(session); // no appid extension

          PublicKeyCredentialRequestOptions options =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, keyHandle)),
                  null,
                  null); // no extensions

          try {
            client.getAssertion(
                TestData.CLIENT_DATA_JSON_GET_PROVIDER,
                options,
                TestData.RP_ID,
                TestData.PIN,
                null);
            fail("getAssertion should fail without the appid extension");
          } catch (ClientError e) {
            // Expected — credential not found under SHA-256("example.com")
          }
        });
  }

  // ── Step 3: appidExclude extension — makeCredential ────────────────────────

  /**
   * Tests that a legacy U2F credential is correctly detected in the exclude list when the {@code
   * appidExclude} extension is supplied.
   *
   * <p>Flow:
   *
   * <ol>
   *   <li>Register via CTAP1.
   *   <li>Open a new CTAP2 session.
   *   <li>Call {@code makeCredential} with the U2F key handle in {@code excludeCredentials} and
   *       {@code extensions.appidExclude = "https://example.com"}.
   *   <li>Expect {@link ClientError} with {@code DEVICE_INELIGIBLE} because the authenticator finds
   *       the legacy credential.
   * </ol>
   */
  public static void testAppIdExcludeMakeCredential(FidoTestState state) throws Throwable {

    byte[] keyHandle = state.withCtap1(AppIdExtensionTests::registerViaCtap1);

    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions =
              Collections.singletonList(
                  new AppIdExcludeExtension() // your implementation
                  );
          Ctap2Client client = createClientWithFacet(session, extensions);

          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appidExclude", LEGACY_APP_ID);

          PublicKeyCredentialCreationOptions options =
              new PublicKeyCredentialCreationOptions(
                  TestData.RP,
                  new PublicKeyCredentialUserEntity(
                      "appidtest", "appidtest".getBytes(StandardCharsets.UTF_8), "AppId Test User"),
                  TestData.CHALLENGE,
                  Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                  (long) 90000,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, keyHandle)),
                  new AuthenticatorSelectionCriteria(
                      null, ResidentKeyRequirement.DISCOURAGED, null),
                  null, // attestation
                  Extensions.fromMap(extMap));

          try {
            client.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE_PROVIDER,
                options,
                Objects.requireNonNull(options.getRp().getId()),
                TestData.PIN,
                null,
                null);
            fail("makeCredential should fail — the U2F credential is in the exclude list");
          } catch (ClientError e) {
            // Expected: DEVICE_INELIGIBLE
          }
        });
  }

  /**
   * Negative test: without appidExclude, the same makeCredential call <em>succeeds</em> because the
   * authenticator only checks {@code SHA-256("example.com")} against the exclude list and misses
   * the credential bound to {@code SHA-256("https://example.com")}.
   */
  public static void testMakeCredentialSucceedsWithoutAppIdExclude(FidoTestState state)
      throws Throwable {

    byte[] keyHandle = state.withCtap1(AppIdExtensionTests::registerViaCtap1);

    state.withCtap2(
        (session, fidoState) -> {
          Ctap2Client client = new Ctap2Client(session); // no appidExclude extension

          PublicKeyCredentialCreationOptions options =
              new PublicKeyCredentialCreationOptions(
                  TestData.RP,
                  new PublicKeyCredentialUserEntity(
                      "appidtest2",
                      "appidtest2".getBytes(StandardCharsets.UTF_8),
                      "AppId Test User 2"),
                  TestData.CHALLENGE,
                  Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                  (long) 90000,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, keyHandle)),
                  new AuthenticatorSelectionCriteria(
                      null, ResidentKeyRequirement.DISCOURAGED, null),
                  null,
                  null); // no extensions

          // Should succeed — the exclude check misses the legacy credential
          PublicKeyCredential cred =
              client.makeCredential(
                  TestData.CLIENT_DATA_JSON_CREATE_PROVIDER,
                  options,
                  Objects.requireNonNull(options.getRp().getId()),
                  TestData.PIN,
                  null,
                  null);
          assertNotNull("makeCredential should succeed without appidExclude", cred);
        });
  }

  // ── Step 4: Sanity check — raw CTAP1 round-trip ────────────────────────────

  /**
   * Baseline test: raw CTAP1 register → CTAP1 authenticate, no CTAP2 involved. Confirms the YubiKey
   * is working and the U2F credential is usable at the protocol level before we layer extensions on
   * top.
   */
  public static void testCtap1RoundTrip(FidoTestState state) throws Throwable {
    state.withCtap1(
        (session, fidoState) -> {
          byte[] keyHandle = registerViaCtap1(session);
          verifyCtap1Authentication(session, keyHandle);
        });
  }

  // ── Step 5: Additional tests for extension output and edge cases ──────────

  /** Test that the appid extension output is true when the appId was actually used. */
  public static void testAppIdExtensionOutputTrue(FidoTestState state) throws Throwable {
    // Register via CTAP1
    byte[] keyHandle = state.withCtap1(AppIdExtensionTests::registerViaCtap1);

    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions = Collections.singletonList(new AppIdExtension());
          Ctap2Client client = createClientWithFacet(session, extensions);

          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appid", LEGACY_APP_ID);

          PublicKeyCredentialRequestOptions options =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, keyHandle)),
                  null,
                  Extensions.fromMap(extMap));

          PublicKeyCredential assertion =
              client.getAssertion(
                  TestData.CLIENT_DATA_JSON_GET_PROVIDER,
                  options,
                  TestData.RP_ID,
                  TestData.PIN,
                  null);

          // Verify the extension output
          assertNotNull("Assertion must not be null", assertion);
          assertNotNull("Assertion response must not be null", assertion.getResponse());

          ClientExtensionResults results = assertion.getClientExtensionResults();
          assertNotNull("Client extension results must not be null", results);

          Object appidResult = results.toMap(SerializationType.JSON).get("appid");
          assertNotNull("Extension output must contain 'appid'", appidResult);
          if (!(appidResult instanceof Boolean)) {
            fail("appid extension output should be a Boolean, got: " + appidResult.getClass());
          }
          if (!((Boolean) appidResult)) {
            fail("appid extension output should be true when used, got false");
          }
        });
  }

  /** Test that the appid extension output is false when the standard RP ID was used. */
  public static void testAppIdExtensionOutputFalse(FidoTestState state) throws Throwable {
    state.withCtap2(
        (session, fidoState) -> {
          // First create a credential with standard CTAP2 (not U2F)
          List<Extension> extensions = Collections.singletonList(new AppIdExtension());
          Ctap2Client client = createClientWithFacet(session, extensions);

          PublicKeyCredentialCreationOptions createOptions =
              new PublicKeyCredentialCreationOptions(
                  TestData.RP,
                  new PublicKeyCredentialUserEntity(
                      "testuser", "testuser".getBytes(StandardCharsets.UTF_8), "Test User"),
                  TestData.CHALLENGE,
                  Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                  (long) 90000,
                  null,
                  new AuthenticatorSelectionCriteria(
                      null, ResidentKeyRequirement.DISCOURAGED, null),
                  null,
                  null);

          PublicKeyCredential credential =
              client.makeCredential(
                  TestData.CLIENT_DATA_JSON_CREATE_PROVIDER,
                  createOptions,
                  TestData.RP_ID,
                  TestData.PIN,
                  null,
                  null);

          // Now try to authenticate with appid extension
          // Since credential was created with normal RP ID, appid won't be used
          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appid", LEGACY_APP_ID);

          PublicKeyCredentialRequestOptions requestOptions =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, credential.getRawId())),
                  null,
                  Extensions.fromMap(extMap));

          PublicKeyCredential assertion =
              client.getAssertion(
                  TestData.CLIENT_DATA_JSON_GET_PROVIDER,
                  requestOptions,
                  TestData.RP_ID,
                  TestData.PIN,
                  null);

          // Verify the extension output is false
          assertNotNull("Assertion must not be null", assertion);
          ClientExtensionResults results = assertion.getClientExtensionResults();
          assertNotNull("Client extension results must not be null", results);

          Object appidResult = results.toMap(SerializationType.JSON).get("appid");
          assertNotNull("Extension output must contain 'appid'", appidResult);
          if (!(appidResult instanceof Boolean)) {
            fail("appid extension output should be a Boolean, got: " + appidResult.getClass());
          }
          if ((Boolean) appidResult) {
            fail("appid extension output should be false when not used, got true");
          }
        });
  }

  /** Test that invalid AppID values are rejected (not valid for the RP ID). */
  public static void testInvalidAppId(FidoTestState state) throws Throwable {
    byte[] keyHandle = state.withCtap1(AppIdExtensionTests::registerViaCtap1);

    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions = Collections.singletonList(new AppIdExtension());
          Ctap2Client client = createClientWithFacet(session, extensions);

          // Use an AppID that is NOT valid for the RP ID
          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appid", "https://evil.com"); // different domain

          PublicKeyCredentialRequestOptions options =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, keyHandle)),
                  null,
                  Extensions.fromMap(extMap));

          try {
            client.getAssertion(
                TestData.CLIENT_DATA_JSON_GET_PROVIDER,
                options,
                TestData.RP_ID,
                TestData.PIN,
                null);
            fail("Should fail - invalid appid should be ignored, credential not found");
          } catch (ClientError e) {
            // Expected - no credentials found because invalid appid was ignored
          }
        });
  }

  /** Test that appidExclude doesn't break when excludeCredentials is empty. */
  public static void testAppIdExcludeEmptyList(FidoTestState state) throws Throwable {
    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions = Collections.singletonList(new AppIdExcludeExtension());
          Ctap2Client client = createClientWithFacet(session, extensions);

          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appidExclude", LEGACY_APP_ID);

          PublicKeyCredentialCreationOptions options =
              new PublicKeyCredentialCreationOptions(
                  TestData.RP,
                  new PublicKeyCredentialUserEntity(
                      "emptytest", "emptytest".getBytes(StandardCharsets.UTF_8), "Empty Test User"),
                  TestData.CHALLENGE,
                  Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                  (long) 90000,
                  Collections.emptyList(), // Empty exclude list
                  new AuthenticatorSelectionCriteria(
                      null, ResidentKeyRequirement.DISCOURAGED, null),
                  null,
                  Extensions.fromMap(extMap));

          // Should succeed - no credentials to exclude
          PublicKeyCredential credential =
              client.makeCredential(
                  TestData.CLIENT_DATA_JSON_CREATE_PROVIDER,
                  options,
                  Objects.requireNonNull(options.getRp().getId()),
                  TestData.PIN,
                  null,
                  null);

          assertNotNull("makeCredential should succeed with empty exclude list", credential);
        });
  }

  /** Test that appidExclude extension produces no client output. */
  public static void testAppIdExcludeNoOutput(FidoTestState state) throws Throwable {
    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions = Collections.singletonList(new AppIdExcludeExtension());
          Ctap2Client client = createClientWithFacet(session, extensions);

          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appidExclude", LEGACY_APP_ID);

          PublicKeyCredentialCreationOptions options =
              new PublicKeyCredentialCreationOptions(
                  TestData.RP,
                  new PublicKeyCredentialUserEntity(
                      "nooutput", "nooutput".getBytes(StandardCharsets.UTF_8), "No Output Test"),
                  TestData.CHALLENGE,
                  Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                  (long) 90000,
                  Collections.emptyList(),
                  new AuthenticatorSelectionCriteria(
                      null, ResidentKeyRequirement.DISCOURAGED, null),
                  null,
                  Extensions.fromMap(extMap));

          PublicKeyCredential credential =
              client.makeCredential(
                  TestData.CLIENT_DATA_JSON_CREATE_PROVIDER,
                  options,
                  Objects.requireNonNull(options.getRp().getId()),
                  TestData.PIN,
                  null,
                  null);

          // Verify no appidExclude in output
          assertNotNull("Credential must not be null", credential);
          ClientExtensionResults results = credential.getClientExtensionResults();
          assertNotNull("Client extension results must not be null", results);

          if (results.toMap(SerializationType.JSON).containsKey("appidExclude")) {
            fail("appidExclude must NOT appear in output");
          }
        });
  }

  /** Test appId extension when allowCredentials is empty (resident key scenario). */
  public static void testAppIdWithResidentKey(FidoTestState state) throws Throwable {
    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions = Collections.singletonList(new AppIdExtension());
          Ctap2Client client = createClientWithFacet(session, extensions);

          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appid", LEGACY_APP_ID);

          // Request without allowCredentials (resident key discovery)
          PublicKeyCredentialRequestOptions options =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  null, // No allowCredentials - discover resident keys
                  null,
                  Extensions.fromMap(extMap));

          try {
            PublicKeyCredential assertion =
                client.getAssertion(
                    TestData.CLIENT_DATA_JSON_GET_PROVIDER,
                    options,
                    TestData.RP_ID,
                    TestData.PIN,
                    null);

            // If we get here, check the extension output
            assertNotNull("Assertion must not be null", assertion);
            ClientExtensionResults results = assertion.getClientExtensionResults();
            assertNotNull("Client extension results must not be null", results);

            // The output should reflect whether appId was used
            if (!results.toMap(SerializationType.JSON).containsKey("appid")) {
              fail("Extension output must contain 'appid'");
            }
          } catch (ClientError e) {
            // May fail if no resident credentials exist - that's ok for this test
            // We're just verifying the code doesn't crash with empty allowCredentials
          }
        });
  }

  public static void testAppIdSkippedWithoutFacetConfiguration(FidoTestState state)
      throws Throwable {
    // The appid extension is best-effort: with no FacetID/verifier configured the client skips it
    // (logging a warning) instead of failing outright. The observable effect is that the credential
    // registered via legacy U2F (stored under the AppID) is not found under the real RP ID, so the
    // assertion fails with DEVICE_INELIGIBLE rather than BAD_REQUEST.
    byte[] keyHandle = state.withCtap1(AppIdExtensionTests::registerViaCtap1);

    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions = Collections.singletonList(new AppIdExtension());
          Ctap2Client client = new Ctap2Client(session, extensions);

          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appid", LEGACY_APP_ID);

          PublicKeyCredentialRequestOptions options =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, keyHandle)),
                  null,
                  Extensions.fromMap(extMap));

          try {
            client.getAssertion(
                TestData.CLIENT_DATA_JSON_GET_PROVIDER,
                options,
                TestData.RP_ID,
                TestData.PIN,
                null);
            fail("getAssertion should not find the legacy credential when appid is skipped");
          } catch (ClientError e) {
            if (e.getErrorCode() != ClientError.Code.DEVICE_INELIGIBLE) {
              fail("Expected DEVICE_INELIGIBLE, got: " + e.getErrorCode());
            }
          }
        });
  }

  public static void testAppIdFailsForUnauthorizedFacet(FidoTestState state) throws Throwable {
    byte[] keyHandle = state.withCtap1(AppIdExtensionTests::registerViaCtap1);

    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions = Collections.singletonList(new AppIdExtension());
          Ctap2Client client =
              createClientWithFacetVerifier(session, extensions, (appId, facetId) -> false);

          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appid", LEGACY_APP_ID);

          PublicKeyCredentialRequestOptions options =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, keyHandle)),
                  null,
                  Extensions.fromMap(extMap));

          try {
            client.getAssertion(
                TestData.CLIENT_DATA_JSON_GET_PROVIDER,
                options,
                TestData.RP_ID,
                TestData.PIN,
                null);
            fail("getAssertion should fail when appid facet is unauthorized");
          } catch (ClientError e) {
            if (e.getErrorCode() != ClientError.Code.BAD_REQUEST) {
              fail("Expected BAD_REQUEST, got: " + e.getErrorCode());
            }
          }
        });
  }

  public static void testAppIdExcludeFailsForUnauthorizedFacet(FidoTestState state)
      throws Throwable {
    byte[] keyHandle = state.withCtap1(AppIdExtensionTests::registerViaCtap1);

    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions = Collections.singletonList(new AppIdExcludeExtension());
          Ctap2Client client =
              createClientWithFacetVerifier(session, extensions, (appId, facetId) -> false);

          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appidExclude", LEGACY_APP_ID);

          PublicKeyCredentialCreationOptions options =
              new PublicKeyCredentialCreationOptions(
                  TestData.RP,
                  new PublicKeyCredentialUserEntity(
                      "appidtest3",
                      "appidtest3".getBytes(StandardCharsets.UTF_8),
                      "AppId Test User 3"),
                  TestData.CHALLENGE,
                  Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                  (long) 90000,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, keyHandle)),
                  new AuthenticatorSelectionCriteria(
                      null, ResidentKeyRequirement.DISCOURAGED, null),
                  null,
                  Extensions.fromMap(extMap));

          try {
            client.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE_PROVIDER,
                options,
                Objects.requireNonNull(options.getRp().getId()),
                TestData.PIN,
                null,
                null);
            fail("makeCredential should fail when appidExclude facet is unauthorized");
          } catch (ClientError e) {
            if (e.getErrorCode() != ClientError.Code.BAD_REQUEST) {
              fail("Expected BAD_REQUEST, got: " + e.getErrorCode());
            }
          }
        });
  }

  // ── Step 6: Consolidated end-to-end (appid + appidExclude on one credential) ──

  /**
   * Consolidated end-to-end test: registers a <em>single</em> legacy U2F credential and then proves
   * both extensions against that same credential in sequence.
   *
   * <p>Requires a key that supports <em>both</em> U2F (CTAP1) and FIDO2 (CTAP2). Some newer keys no
   * longer implement U2F; without a U2F-bound credential there is nothing to exercise, so on such a
   * key this test is skipped (via a JUnit assumption) rather than failed.
   *
   * <ol>
   *   <li>Skip unless the CTAP2 {@code getInfo} versions list reports both {@code U2F_V2} and a
   *       {@code FIDO_2_*} version.
   *   <li>Register one credential via raw CTAP1, bound to {@code SHA-256(LEGACY_APP_ID)}.
   *   <li>{@code appid}: a CTAP2 getAssertion for the real RP ID finds that credential and reports
   *       {@code appid: true}.
   *   <li>{@code appidExclude}: a CTAP2 makeCredential listing the same key handle is blocked with
   *       {@link ClientError.Code#DEVICE_INELIGIBLE}.
   * </ol>
   */
  public static void testAppIdAndAppIdExcludeEndToEnd(FidoTestState state) throws Throwable {

    // Guard: require both U2F and FIDO2. A single CTAP2 getInfo reports both capabilities.
    state.withCtap2(
        (session, fidoState) -> {
          List<String> versions = session.getCachedInfo().getVersions();
          assumeTrue(
              "Key does not support U2F (CTAP1); appid/appidExclude need a legacy U2F credential",
              versions.contains("U2F_V2"));
          assumeTrue(
              "Key does not support FIDO2 (CTAP2)",
              versions.contains("FIDO_2_0")
                  || versions.contains("FIDO_2_1")
                  || versions.contains("FIDO_2_3"));
        });

    // Step 1: create ONE legacy U2F credential via raw CTAP1.
    byte[] keyHandle = state.withCtap1(AppIdExtensionTests::registerViaCtap1);

    // Step 2: appid — authenticate with that credential and confirm the output is true.
    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions = Collections.singletonList(new AppIdExtension());
          Ctap2Client client = createClientWithFacet(session, extensions);

          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appid", LEGACY_APP_ID);

          PublicKeyCredentialRequestOptions options =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, keyHandle)),
                  null,
                  Extensions.fromMap(extMap));

          PublicKeyCredential assertion =
              client.getAssertion(
                  TestData.CLIENT_DATA_JSON_GET_PROVIDER,
                  options,
                  TestData.RP_ID,
                  TestData.PIN,
                  null);

          assertNotNull("appid assertion must succeed for the U2F credential", assertion);
          Object appidResult =
              assertion.getClientExtensionResults().toMap(SerializationType.JSON).get("appid");
          if (!Boolean.TRUE.equals(appidResult)) {
            fail("appid extension output should be true, got: " + appidResult);
          }
        });

    // Step 3: appidExclude — the same credential must block a new registration.
    state.withCtap2(
        (session, fidoState) -> {
          List<Extension> extensions = Collections.singletonList(new AppIdExcludeExtension());
          Ctap2Client client = createClientWithFacet(session, extensions);

          Map<String, Object> extMap = new HashMap<>();
          extMap.put("appidExclude", LEGACY_APP_ID);

          PublicKeyCredentialCreationOptions options =
              new PublicKeyCredentialCreationOptions(
                  TestData.RP,
                  new PublicKeyCredentialUserEntity(
                      "appide2e", "appide2e".getBytes(StandardCharsets.UTF_8), "AppId E2E User"),
                  TestData.CHALLENGE,
                  Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                  (long) 90000,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, keyHandle)),
                  new AuthenticatorSelectionCriteria(
                      null, ResidentKeyRequirement.DISCOURAGED, null),
                  null,
                  Extensions.fromMap(extMap));

          try {
            client.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE_PROVIDER,
                options,
                Objects.requireNonNull(options.getRp().getId()),
                TestData.PIN,
                null,
                null);
            fail("appidExclude should block re-registering the excluded U2F credential");
          } catch (ClientError e) {
            if (e.getErrorCode() != ClientError.Code.DEVICE_INELIGIBLE) {
              fail("Expected DEVICE_INELIGIBLE, got: " + e.getErrorCode());
            }
          }
        });
  }
}

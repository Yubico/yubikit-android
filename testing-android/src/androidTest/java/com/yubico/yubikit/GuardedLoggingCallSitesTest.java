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

package com.yubico.yubikit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import android.util.Log;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.Cose;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Drives SDK production code whose logging was converted from the SLF4J 2.x fluent API to {@code
 * isXEnabled()}-guarded plain calls, and asserts it survives on the device under test.
 *
 * <p>{@code LoggingSmokeTests} covers the call <em>shapes</em> in isolation against a logger it
 * creates itself. This covers the real thing: {@link Cose} is reachable without a YubiKey and holds
 * six converted call sites spanning all three key types - {@code publicKey} in {@code
 * getPublicKey}, {@code raw} for Ed25519, {@code x}/{@code y} for EC2 and {@code n}/{@code e} for
 * RSA.
 *
 * <p>Before the conversion every one of those was {@code logger.atDebug()}, which on an APK built
 * at {@code minSdk < 24} throws {@code AbstractMethodError} on a modern device and takes the whole
 * instrumentation process down with a native SIGSEGV on API 21. {@code testing-android} builds at
 * {@code minSdk 21}, and its {@code logback.xml} sets the root level to TRACE, so the guards do not
 * short-circuit - the converted bodies really execute and really format their arguments. Reaching
 * the end of a test method is therefore the assertion that matters; a regression here does not fail
 * the test, it kills the process.
 */
@RunWith(AndroidJUnit4.class)
public class GuardedLoggingCallSitesTest {

  private static final String TAG = "GuardedLoggingCallSites";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES256_X = "wYXQNcHYEQHhLWssYM3Wxh59Glcd27iQRAbH7g73zEc";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES256_Y = "8N523zR8MPQ3VGVV0Qm1hE1f0BEG9z4mQISHWpo6XXw";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String RS256_N =
      "0KeO-wuDQK18v9WwN5hFe6G_1TM4Ra8alOFa8cyN9xfqaLK1TvYVQHZfOcVvgM5XztCEOPNcQ5AWMJmTOESwvjuHkj5"
          + "ulGt2jCVJUWKxPX-KYq0UFlb5jr305D66p5vRKb7zBterpDJSOxwLKr7g9jVhgpM2mgVjrRnQPMUAfvt8q9QM"
          + "UWy1eIgIxnABi9b28cZ6WBDi42LMYiHz8mfUWi_ga9TASAwTqYZmGFUr7Z71ZuPKxuOxsgTxUksqKEmJw8iWc"
          + "CgTC6-O8sMe-aZ3gqcwDEk9kRKZQJKlxtyYuArn2zDKfaAHJ1A2wLwjtq8m_TsiOEdW3289Fe_F4gSA_w";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String RS256_E = "AAEAAQ";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String EDDSA_RAW_KEY = "3wIKsJK63Ctb-nLkcwG8fJOp2vZxz8lmhv3BcFI-ves";

  private static Map<Integer, Object> es256() {
    Map<Integer, Object> key = new HashMap<>();
    key.put(1, 2); // kty
    key.put(3, -7); // alg
    key.put(-1, 1); // crv
    key.put(-2, Base64.fromUrlSafeString(ES256_X));
    key.put(-3, Base64.fromUrlSafeString(ES256_Y));
    return key;
  }

  private static Map<Integer, Object> rs256() {
    Map<Integer, Object> key = new HashMap<>();
    key.put(1, 3); // kty
    key.put(3, -257); // alg
    key.put(-1, Base64.fromUrlSafeString(RS256_N));
    key.put(-2, Base64.fromUrlSafeString(RS256_E));
    return key;
  }

  private static Map<Integer, Object> eddsa() {
    Map<Integer, Object> key = new HashMap<>();
    key.put(1, 1); // kty
    key.put(3, -8); // alg
    key.put(-1, 6); // crv
    key.put(-2, Base64.fromUrlSafeString(EDDSA_RAW_KEY));
    return key;
  }

  /** Exercises the {@code x}/{@code y} sites plus the shared {@code publicKey} site. */
  @Test
  public void ec2CallSites() throws Exception {
    PublicKey publicKey = Cose.getPublicKey(es256());

    assertNotNull("EC2 key did not decode", publicKey);
    assertEquals("EC", publicKey.getAlgorithm());
    Log.i(TAG, "EC2 call sites OK: " + publicKey.getAlgorithm());
  }

  /** Exercises the {@code n}/{@code e} sites plus the shared {@code publicKey} site. */
  @Test
  public void rsaCallSites() throws Exception {
    PublicKey publicKey = Cose.getPublicKey(rs256());

    assertNotNull("RSA key did not decode", publicKey);
    assertEquals("RSA", publicKey.getAlgorithm());
    Log.i(TAG, "RSA call sites OK: " + publicKey.getAlgorithm());
  }

  /**
   * Exercises the Ed25519 {@code raw} site.
   *
   * <p>Android had no Ed25519 provider until API 33, so {@code toPublicKey()} is expected to throw
   * on an old device. That is irrelevant here: the converted log statement runs before it, so
   * catching the provider failure and returning normally still proves the call site is safe. What
   * would fail is the process dying before the catch.
   */
  @Test
  public void ed25519CallSite() {
    try {
      PublicKey publicKey = Cose.getPublicKey(eddsa());
      Log.i(TAG, "Ed25519 call site OK, key decoded: " + publicKey);
    } catch (Exception e) {
      Log.i(TAG, "Ed25519 call site OK, no provider on this device: " + e);
    }
  }

  /** The plain, never-converted call in {@code getAlgorithm}, as a control. */
  @Test
  public void plainCallSiteControl() {
    assertEquals(Integer.valueOf(-7), Cose.getAlgorithm(es256()));
    assertEquals(Integer.valueOf(-257), Cose.getAlgorithm(rs256()));
    Log.i(TAG, "plain control OK");
  }
}

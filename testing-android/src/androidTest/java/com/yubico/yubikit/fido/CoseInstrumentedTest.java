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

package com.yubico.yubikit.fido;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Device-side counterpart to {@code CoseTest} in the fido module, sharing its vectors via {@link
 * CoseTestVectors}.
 *
 * <p>The JVM unit test exercises {@link Cose#getPublicKey} against the JDK's SunEC provider. This
 * one runs the same vectors against whatever {@code KeyFactory.getInstance("EC")} resolves to on a
 * real device (Conscrypt / BoringSSL), which is the provider that actually decodes credential
 * public keys in production. The two disagree on an off-curve point: SunEC accepts it and returns a
 * silently wrong key, Conscrypt throws {@link InvalidKeySpecException}. Both are failures and
 * {@link CoseTestVectors#assertRoundTrip} catches either.
 *
 * <p>Needs no YubiKey, so it is deliberately not a member of any of the hardware test suites. Run
 * it with:
 *
 * <pre>
 * ./gradlew :testing-android:connectedDebugAndroidTest \
 *     -Pandroid.testInstrumentationRunnerArguments.class=\
 * com.yubico.yubikit.fido.CoseInstrumentedTest
 * </pre>
 */
@RunWith(AndroidJUnit4.class)
public class CoseInstrumentedTest {

  @Test
  public void getPublicKeyES256TruncatingX()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    CoseTestVectors.assertRoundTrip(CoseTestVectors.ES256_TRUNCATING_X);
  }

  @Test
  public void getPublicKeyES256TruncatingY()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    CoseTestVectors.assertRoundTrip(CoseTestVectors.ES256_TRUNCATING_Y);
  }

  @Test
  public void getPublicKeyES384TruncatingX()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    CoseTestVectors.assertRoundTrip(CoseTestVectors.ES384_TRUNCATING_X);
  }

  @Test
  public void getPublicKeyES256LeadingFf()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    CoseTestVectors.assertRoundTrip(CoseTestVectors.ES256_LEADING_FF);
  }
}

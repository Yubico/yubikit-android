/*
 * Copyright (C) 2023 Yubico.
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

import com.yubico.yubikit.core.internal.codec.Base64;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;

public class CoseTest {

  private static final Map<Integer, Object> EMPTY_COSE = new HashMap<>();

  private static final Map<Integer, Object> RS256 = new HashMap<>();

  @SuppressWarnings("SpellCheckingInspection")
  private static final String RS256_PUB =
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KeO-wuDQK18v9WwN5hFe6G_1TM4Ra8alOFa8cyN9xfqaLK"
          + "1TvYVQHZfOcVvgM5XztCEOPNcQ5AWMJmTOESwvjuHkj5ulGt2jCVJUWKxPX-KYq0UFlb5jr305D66p5vRKb7z"
          + "BterpDJSOxwLKr7g9jVhgpM2mgVjrRnQPMUAfvt8q9QMUWy1eIgIxnABi9b28cZ6WBDi42LMYiHz8mfUWi_ga"
          + "9TASAwTqYZmGFUr7Z71ZuPKxuOxsgTxUksqKEmJw8iWcCgTC6-O8sMe-aZ3gqcwDEk9kRKZQJKlxtyYuArn2z"
          + "DKfaAHJ1A2wLwjtq8m_TsiOEdW3289Fe_F4gSA_wIDAQAB";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String RS256_N =
      "0KeO-wuDQK18v9WwN5hFe6G_1TM4Ra8alOFa8cyN9xfqaLK1TvYVQHZfOcVvgM5XztCEOPNcQ5AWMJmTOESwvjuHkj5"
          + "ulGt2jCVJUWKxPX-KYq0UFlb5jr305D66p5vRKb7zBterpDJSOxwLKr7g9jVhgpM2mgVjrRnQPMUAfvt8q9QM"
          + "UWy1eIgIxnABi9b28cZ6WBDi42LMYiHz8mfUWi_ga9TASAwTqYZmGFUr7Z71ZuPKxuOxsgTxUksqKEmJw8iWc"
          + "CgTC6-O8sMe-aZ3gqcwDEk9kRKZQJKlxtyYuArn2zDKfaAHJ1A2wLwjtq8m_TsiOEdW3289Fe_F4gSA_w";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String RS256_E = "AAEAAQ";

  private static final Map<Integer, Object> ES256 = new HashMap<>();

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES256_PUB =
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwYXQNcHYEQHhLWssYM3Wxh59Glcd27iQRAbH7g73zEfw3nbfNHww9Dd"
          + "UZVXRCbWETV_QEQb3PiZAhIdamjpdfA";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES256_X = "wYXQNcHYEQHhLWssYM3Wxh59Glcd27iQRAbH7g73zEc";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES256_Y = "8N523zR8MPQ3VGVV0Qm1hE1f0BEG9z4mQISHWpo6XXw";

  private static final Map<Integer, Object> ES384 = new HashMap<>();

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES384_PUB =
      "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEetBCP2oYwt-gkaDtb4eRy_QwdcywdSYvTtzpXMNxwfby4npVyJJ1yktnFhg"
          + "i9ftU1VpkK0DSb8XIv-k7cJiU5eT1m8YYu8nlV7hKCz5_YzDtsprXCaHMhv37XGiENkLp";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES384_X =
      "etBCP2oYwt-gkaDtb4eRy_QwdcywdSYvTtzpXMNxwfby4npVyJJ1yktnFhgi9ftU";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES384_Y =
      "1VpkK0DSb8XIv-k7cJiU5eT1m8YYu8nlV7hKCz5_YzDtsprXCaHMhv37XGiENkLp";

  private static final Map<Integer, Object> ES512 = new HashMap<>();

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES512_PUB =
      "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBt0sGA8_brqo0_oRLGGxxndU6NZAsPLE0Bi6IS6MCoNILVI6uonHWOTM"
          + "sfM2hoD5AM2Jm1VM8tQwC41jGxzQD6Q4BBMI0mQapyTTeA5SpUnZDN7fnbkRHAU2BzOLTvzWA2y6R8f87ghp-"
          + "2pRtn_mKEqjzJLjOW0-ECHjmMiLGH8Qww88";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES512_X =
      "AbdLBgPP266qNP6ESxhscZ3VOjWQLDyxNAYuiEujAqDSC1SOrqJx1jkzLHzNoaA-QDNiZtVTPLUMAuNYxsc0A-kO";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES512_Y =
      "AQTCNJkGqck03gOUqVJ2Qze3525ERwFNgczi0781gNsukfH_O4IaftqUbZ_5ihKo8yS4zltPhAh45jIixh_EMMPP";

  private static final Map<Integer, Object> EDDSA = new HashMap<>();

  @SuppressWarnings("SpellCheckingInspection")
  private static final String EDDSA_PUB =
      "MCowBQYDK2VwAyEA3wIKsJK63Ctb-nLkcwG8fJOp2vZxz8lmhv3BcFI-ves";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String EDDSA_RAW_KEY = "3wIKsJK63Ctb-nLkcwG8fJOp2vZxz8lmhv3BcFI-ves";

  static {
    RS256.put(1, 3); // kty
    RS256.put(3, -257); // alg
    RS256.put(-1, decode(RS256_N)); // n
    RS256.put(-2, decode(RS256_E)); // e

    ES256.put(1, 2); // kty
    ES256.put(3, -7); // alg
    ES256.put(-1, 1); // crv
    ES256.put(-2, decode(ES256_X)); // x
    ES256.put(-3, decode(ES256_Y)); // y

    ES384.put(1, 2); // kty
    ES384.put(3, -7); // alg
    ES384.put(-1, 2); // crv
    ES384.put(-2, decode(ES384_X)); // x
    ES384.put(-3, decode(ES384_Y)); // y

    ES512.put(1, 2); // kty
    ES512.put(3, -7); // alg
    ES512.put(-1, 3); // crv
    ES512.put(-2, decode(ES512_X)); // x
    ES512.put(-3, decode(ES512_Y)); // y

    EDDSA.put(1, 1); // kty
    EDDSA.put(3, -8); // alg
    EDDSA.put(-1, 6); // crv
    EDDSA.put(-2, decode(EDDSA_RAW_KEY)); // raw key
  }

  private static byte[] decode(String urlSafeBase64) {
    return Base64.fromUrlSafeString(urlSafeBase64);
  }

  private static String encode(byte[] data) {
    return Base64.toUrlSafeString(data);
  }

  @Test(expected = NullPointerException.class)
  public void getAlgorithmOnInvalidData() {
    Assert.assertNull(Cose.getAlgorithm(EMPTY_COSE));
  }

  @Test
  public void getAlgorithm() {
    Assert.assertEquals(Integer.valueOf(-257), Cose.getAlgorithm(RS256));
    Assert.assertEquals(Integer.valueOf(-7), Cose.getAlgorithm(ES256));
    Assert.assertEquals(Integer.valueOf(-7), Cose.getAlgorithm(ES384));
    Assert.assertEquals(Integer.valueOf(-7), Cose.getAlgorithm(ES512));
    Assert.assertEquals(Integer.valueOf(-8), Cose.getAlgorithm(EDDSA));
  }

  @Test
  public void getPublicKeyRS256()
      throws InvalidKeySpecException, NoSuchAlgorithmException, NullPointerException {
    PublicKey publicKey = Cose.getPublicKey(RS256);
    Assert.assertNotNull(publicKey);
    Assert.assertEquals(RS256_PUB, encode(publicKey.getEncoded()));
  }

  @Test
  public void getPublicKeyES256()
      throws InvalidKeySpecException, NoSuchAlgorithmException, NullPointerException {
    PublicKey publicKey = Cose.getPublicKey(ES256);
    Assert.assertNotNull(publicKey);
    Assert.assertEquals(ES256_PUB, encode(publicKey.getEncoded()));
  }

  @Test
  public void getPublicKeyES384()
      throws InvalidKeySpecException, NoSuchAlgorithmException, NullPointerException {
    PublicKey publicKey = Cose.getPublicKey(ES384);
    Assert.assertNotNull(publicKey);
    Assert.assertEquals(ES384_PUB, encode(publicKey.getEncoded()));
  }

  @Test
  public void getPublicKeyES512()
      throws InvalidKeySpecException, NoSuchAlgorithmException, NullPointerException {
    PublicKey publicKey = Cose.getPublicKey(ES512);
    Assert.assertNotNull(publicKey);
    Assert.assertEquals(ES512_PUB, encode(publicKey.getEncoded()));
  }

  @Test
  public void getPublicKeyEDDSA()
      throws InvalidKeySpecException, NoSuchAlgorithmException, NullPointerException {
    PublicKey publicKey = Cose.getPublicKey(EDDSA);
    Assert.assertNotNull(publicKey);
    Assert.assertEquals(EDDSA_PUB, encode(publicKey.getEncoded()));
  }
}

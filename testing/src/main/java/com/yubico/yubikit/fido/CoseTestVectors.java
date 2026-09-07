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

import com.yubico.yubikit.Codec;
import com.yubico.yubikit.core.internal.codec.Base64;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;

/**
 * Shared COSE test vectors. Exercises standard key parsing across algorithms and tests unsigned
 * decoding edge cases where leading 0xFF bytes trigger truncation.
 */
public final class CoseTestVectors {

  private CoseTestVectors() {}

  private static final String ES256_X = "wYXQNcHYEQHhLWssYM3Wxh59Glcd27iQRAbH7g73zEc";

  private static final String ES256_Y = "8N523zR8MPQ3VGVV0Qm1hE1f0BEG9z4mQISHWpo6XXw";

  public static final String ES256_SPKI =
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwYXQNcHYEQHhLWssYM3Wxh59Glcd27iQRAbH7g73zEfw3nbfNHww9Dd"
          + "UZVXRCbWETV_QEQb3PiZAhIdamjpdfA";

  private static final String ES384_X =
      "etBCP2oYwt-gkaDtb4eRy_QwdcywdSYvTtzpXMNxwfby4npVyJJ1yktnFhgi9ftU";

  private static final String ES384_Y =
      "1VpkK0DSb8XIv-k7cJiU5eT1m8YYu8nlV7hKCz5_YzDtsprXCaHMhv37XGiENkLp";

  public static final String ES384_SPKI =
      "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEetBCP2oYwt-gkaDtb4eRy_QwdcywdSYvTtzpXMNxwfby4npVyJJ1yktnFhg"
          + "i9ftU1VpkK0DSb8XIv-k7cJiU5eT1m8YYu8nlV7hKCz5_YzDtsprXCaHMhv37XGiENkLp";

  private static final String ES512_X =
      "AbdLBgPP266qNP6ESxhscZ3VOjWQLDyxNAYuiEujAqDSC1SOrqJx1jkzLHzNoaA-QDNiZtVTPLUMAuNYxsc0A-kO";

  private static final String ES512_Y =
      "AQTCNJkGqck03gOUqVJ2Qze3525ERwFNgczi0781gNsukfH_O4IaftqUbZ_5ihKo8yS4zltPhAh45jIixh_EMMPP";

  public static final String ES512_SPKI =
      "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBt0sGA8_brqo0_oRLGGxxndU6NZAsPLE0Bi6IS6MCoNILVI6uonHWOTM"
          + "sfM2hoD5AM2Jm1VM8tQwC41jGxzQD6Q4BBMI0mQapyTTeA5SpUnZDN7fnbkRHAU2BzOLTvzWA2y6R8f87ghp-"
          + "2pRtn_mKEqjzJLjOW0-ECHjmMiLGH8Qww88";

  private static final String RS256_N =
      "0KeO-wuDQK18v9WwN5hFe6G_1TM4Ra8alOFa8cyN9xfqaLK1TvYVQHZfOcVvgM5XztCEOPNcQ5AWMJmTOESwvjuHkj5"
          + "ulGt2jCVJUWKxPX-KYq0UFlb5jr305D66p5vRKb7zBterpDJSOxwLKr7g9jVhgpM2mgVjrRnQPMUAfvt8q9QM"
          + "UWy1eIgIxnABi9b28cZ6WBDi42LMYiHz8mfUWi_ga9TASAwTqYZmGFUr7Z71ZuPKxuOxsgTxUksqKEmJw8iWc"
          + "CgTC6-O8sMe-aZ3gqcwDEk9kRKZQJKlxtyYuArn2zDKfaAHJ1A2wLwjtq8m_TsiOEdW3289Fe_F4gSA_w";

  private static final String RS256_E = "AAEAAQ";

  public static final String RS256_SPKI =
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KeO-wuDQK18v9WwN5hFe6G_1TM4Ra8alOFa8cyN9xfqaLK"
          + "1TvYVQHZfOcVvgM5XztCEOPNcQ5AWMJmTOESwvjuHkj5ulGt2jCVJUWKxPX-KYq0UFlb5jr305D66p5vRKb7z"
          + "BterpDJSOxwLKr7g9jVhgpM2mgVjrRnQPMUAfvt8q9QMUWy1eIgIxnABi9b28cZ6WBDi42LMYiHz8mfUWi_ga"
          + "9TASAwTqYZmGFUr7Z71ZuPKxuOxsgTxUksqKEmJw8iWcCgTC6-O8sMe-aZ3gqcwDEk9kRKZQJKlxtyYuArn2z"
          + "DKfaAHJ1A2wLwjtq8m_TsiOEdW3289Fe_F4gSA_wIDAQAB";

  private static final String EDDSA_RAW_KEY = "3wIKsJK63Ctb-nLkcwG8fJOp2vZxz8lmhv3BcFI-ves";

  public static final String EDDSA_SPKI =
      "MCowBQYDK2VwAyEA3wIKsJK63Ctb-nLkcwG8fJOp2vZxz8lmhv3BcFI-ves";

  public static Map<Integer, Object> es256() {
    return ec2Key(-7, 1, Base64.fromUrlSafeString(ES256_X), Base64.fromUrlSafeString(ES256_Y));
  }

  public static Map<Integer, Object> es384() {
    return ec2Key(-35, 2, Base64.fromUrlSafeString(ES384_X), Base64.fromUrlSafeString(ES384_Y));
  }

  public static Map<Integer, Object> es512() {
    return ec2Key(-36, 3, Base64.fromUrlSafeString(ES512_X), Base64.fromUrlSafeString(ES512_Y));
  }

  public static Map<Integer, Object> rs256() {
    Map<Integer, Object> cose = new HashMap<>();
    cose.put(1, 3); // kty: RSA
    cose.put(3, -257); // alg
    cose.put(-1, Base64.fromUrlSafeString(RS256_N)); // n
    cose.put(-2, Base64.fromUrlSafeString(RS256_E)); // e
    return cose;
  }

  public static Map<Integer, Object> eddsa() {
    Map<Integer, Object> cose = new HashMap<>();
    cose.put(1, 1); // kty: OKP
    cose.put(3, -8); // alg
    cose.put(-1, 6); // crv: Ed25519
    cose.put(-2, Base64.fromUrlSafeString(EDDSA_RAW_KEY)); // raw key
    return cose;
  }

  private static Map<Integer, Object> ec2Key(int algorithm, int curve, byte[] x, byte[] y) {
    Map<Integer, Object> cose = new HashMap<>();
    cose.put(1, 2); // kty: EC2
    cose.put(3, algorithm); // alg
    cose.put(-1, curve); // crv
    cose.put(-2, x); // x
    cose.put(-3, y); // y
    return cose;
  }

  public static final class Vector {
    private final int algorithm;
    private final int curve;
    private final String x;
    private final String y;
    private final String spki;

    Vector(int algorithm, int curve, String x, String y, String spki) {
      this.algorithm = algorithm;
      this.curve = curve;
      this.x = x;
      this.y = y;
      this.spki = spki;
    }

    /** The COSE key as {@link Cose#getPublicKey} expects it. */
    public Map<Integer, Object> toCoseKey() {
      return ec2Key(algorithm, curve, Codec.fromHex(x), Codec.fromHex(y));
    }

    public BigInteger affineX() {
      return new BigInteger(1, Codec.fromHex(x));
    }

    public BigInteger affineY() {
      return new BigInteger(1, Codec.fromHex(y));
    }

    /** Independently computed X.509 SubjectPublicKeyInfo, url-safe base64. */
    public String expectedSpki() {
      return spki;
    }
  }

  // SECP256R1 vector with redundant leading 0xFF in x
  public static final Vector ES256_TRUNCATING_X =
      new Vector(
          -7,
          1,
          "ff9f4aa102ef0ff733e9f8c4e5e6df114596d6c94ad81ac237b0ef9ef004ee81",
          "238b7bfb3be7c9be1af55766343a0c7022fe93b9bf9a44d2a694cef7900dbfce",
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE_59KoQLvD_cz6fjE5ebfEUWW1slK2BrCN7DvnvAE7oEji3v7O-fJ"
              + "vhr1V2Y0OgxwIv6Tub-aRNKmlM73kA2_zg");

  // SECP256R1 vector with redundant leading 0xFF in y
  public static final Vector ES256_TRUNCATING_Y =
      new Vector(
          -7,
          1,
          "edc4254f9e0612569c4be857c7d09a60cd4555e867909c76471cb2ed420cd819",
          "ffa06b06845c31ec9b81bc4ca122ed16b083f7e9d263bc475e864937171cecfe",
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7cQlT54GElacS-hXx9CaYM1FVehnkJx2Rxyy7UIM2Bn_oGsGhFwx"
              + "7JuBvEyhIu0WsIP36dJjvEdehkk3Fxzs_g");

  // SECP384R1 vector verifying multi-width coordinate truncation
  public static final Vector ES384_TRUNCATING_X =
      new Vector(
          -35,
          2,
          "ffcfb755a5e51c0eabb58a20633be121e273410334f3a2dba0d5e47e9c30a726"
              + "05750cd9ccf23442fe6c04394b7767a8",
          "535005ec1a4ed4c12eac1318ca9a5e9b35d7620c1705b4321aa01c4d11375281"
              + "4d190b8462a0742f3e312418af13d52e",
          "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE_8-3VaXlHA6rtYogYzvhIeJzQQM086LboNXkfpwwpyYFdQzZzPI0Qv5s"
              + "BDlLd2eoU1AF7BpO1MEurBMYyppemzXXYgwXBbQyGqAcTRE3UoFNGQuEYqB0Lz4xJBivE9Uu");

  // Boundary check: non-redundant leading 0xFF that must not be stripped
  public static final Vector ES256_LEADING_FF =
      new Vector(
          -7,
          1,
          "ff229b98c9e2fbdc6b5b80a7aa28f671d6ffc7444f069bb1c9f4c3a13b0610f9",
          "e6593b7734faaa4aa0db2934b3df4a91bfb3f221c986b4add02665720b321023",
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE_yKbmMni-9xrW4Cnqij2cdb_x0RPBpuxyfTDoTsGEPnmWTt3NPqq"
              + "SqDbKTSz30qRv7PyIcmGtK3QJmVyCzIQIw");

  /**
   * Asserts that affine coordinates and SPKI encodings round-trip cleanly without silent provider
   * failures.
   */
  public static void assertRoundTrip(Vector vector)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    PublicKey publicKey = Cose.getPublicKey(vector.toCoseKey());
    Assert.assertNotNull(publicKey);
    ECPoint point = ((ECPublicKey) publicKey).getW();
    Assert.assertEquals("affine x", vector.affineX(), point.getAffineX());
    Assert.assertEquals("affine y", vector.affineY(), point.getAffineY());
    Assert.assertEquals(vector.expectedSpki(), Base64.toUrlSafeString(publicKey.getEncoded()));
  }
}

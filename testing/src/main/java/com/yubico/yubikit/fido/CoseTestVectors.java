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
 * Shared COSE test vectors.
 *
 * <p>Two groups, serving different purposes.
 *
 * <p><b>Standard keys</b> — {@link #es256()}, {@link #es384()}, {@link #es512()}, {@link #rs256()}
 * and {@link #eddsa()}, one well-formed key per supported algorithm, each paired with an {@code
 * *_SPKI} constant. For callers that just need a valid COSE key of a given type. Their coordinates
 * stay in url-safe base64, the form they have always been in.
 *
 * <p><b>Regression vectors</b> — the {@code *_TRUNCATING_*} and {@link #ES256_LEADING_FF} {@link
 * Vector}s below, which exist to pin one specific decoding defect and carry hex coordinates so the
 * byte pattern under test stays readable.
 *
 * <h2>The defect the regression vectors cover</h2>
 *
 * <p>COSE encodes x and y as fixed-width unsigned big-endian integers (RFC 9053 7.1.1). Reading one
 * with the signed {@code BigInteger(byte[])} constructor makes any coordinate with the high bit set
 * negative. That alone is usually harmless, because the minimal two's complement form of such a
 * value is still the same width and re-encodes to the original bytes. It stops being harmless when
 * the leading 0xFF is redundant, i.e. when the second byte also has its high bit set: the minimal
 * form is then one byte shorter, and {@code ByteUtils.intToLength} left-pads it with 0x00, turning
 * the leading 0xFF into 0x00 and producing a different key.
 *
 * <p>That is P(first byte == 0xFF) * P(second byte &gt;= 0x80) = 1/512 per coordinate, so roughly
 * one EC credential in 256. SECP521R1 cannot be affected: its 66-byte coordinates always begin 0x00
 * or 0x01.
 *
 * <p>These vectors live here so the JVM unit test and the Android instrumented test assert on one
 * source of truth. They are worth running against more than one provider: an incorrect coordinate
 * yields a point that is not on the curve, and providers disagree on whether that is fatal. SunEC
 * accepts it and hands back a silently wrong key; Conscrypt rejects it with an {@link
 * InvalidKeySpecException}.
 *
 * <p>Every vector is a small multiple of its curve generator, so it is a genuine point on the curve
 * and a conforming decoder must round-trip it exactly. Coordinates are hex rather than base64 so
 * that the leading byte pattern under test stays readable.
 */
public final class CoseTestVectors {

  private CoseTestVectors() {}

  // ---------------------------------------------------------------------------------------------
  // Standard keys — one well-formed key per algorithm, with the SPKI a correct decoder produces.
  // ---------------------------------------------------------------------------------------------

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES256_X = "wYXQNcHYEQHhLWssYM3Wxh59Glcd27iQRAbH7g73zEc";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES256_Y = "8N523zR8MPQ3VGVV0Qm1hE1f0BEG9z4mQISHWpo6XXw";

  @SuppressWarnings("SpellCheckingInspection")
  public static final String ES256_SPKI =
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwYXQNcHYEQHhLWssYM3Wxh59Glcd27iQRAbH7g73zEfw3nbfNHww9Dd"
          + "UZVXRCbWETV_QEQb3PiZAhIdamjpdfA";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES384_X =
      "etBCP2oYwt-gkaDtb4eRy_QwdcywdSYvTtzpXMNxwfby4npVyJJ1yktnFhgi9ftU";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES384_Y =
      "1VpkK0DSb8XIv-k7cJiU5eT1m8YYu8nlV7hKCz5_YzDtsprXCaHMhv37XGiENkLp";

  @SuppressWarnings("SpellCheckingInspection")
  public static final String ES384_SPKI =
      "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEetBCP2oYwt-gkaDtb4eRy_QwdcywdSYvTtzpXMNxwfby4npVyJJ1yktnFhg"
          + "i9ftU1VpkK0DSb8XIv-k7cJiU5eT1m8YYu8nlV7hKCz5_YzDtsprXCaHMhv37XGiENkLp";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES512_X =
      "AbdLBgPP266qNP6ESxhscZ3VOjWQLDyxNAYuiEujAqDSC1SOrqJx1jkzLHzNoaA-QDNiZtVTPLUMAuNYxsc0A-kO";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String ES512_Y =
      "AQTCNJkGqck03gOUqVJ2Qze3525ERwFNgczi0781gNsukfH_O4IaftqUbZ_5ihKo8yS4zltPhAh45jIixh_EMMPP";

  @SuppressWarnings("SpellCheckingInspection")
  public static final String ES512_SPKI =
      "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBt0sGA8_brqo0_oRLGGxxndU6NZAsPLE0Bi6IS6MCoNILVI6uonHWOTM"
          + "sfM2hoD5AM2Jm1VM8tQwC41jGxzQD6Q4BBMI0mQapyTTeA5SpUnZDN7fnbkRHAU2BzOLTvzWA2y6R8f87ghp-"
          + "2pRtn_mKEqjzJLjOW0-ECHjmMiLGH8Qww88";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String RS256_N =
      "0KeO-wuDQK18v9WwN5hFe6G_1TM4Ra8alOFa8cyN9xfqaLK1TvYVQHZfOcVvgM5XztCEOPNcQ5AWMJmTOESwvjuHkj5"
          + "ulGt2jCVJUWKxPX-KYq0UFlb5jr305D66p5vRKb7zBterpDJSOxwLKr7g9jVhgpM2mgVjrRnQPMUAfvt8q9QM"
          + "UWy1eIgIxnABi9b28cZ6WBDi42LMYiHz8mfUWi_ga9TASAwTqYZmGFUr7Z71ZuPKxuOxsgTxUksqKEmJw8iWc"
          + "CgTC6-O8sMe-aZ3gqcwDEk9kRKZQJKlxtyYuArn2zDKfaAHJ1A2wLwjtq8m_TsiOEdW3289Fe_F4gSA_w";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String RS256_E = "AAEAAQ";

  @SuppressWarnings("SpellCheckingInspection")
  public static final String RS256_SPKI =
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KeO-wuDQK18v9WwN5hFe6G_1TM4Ra8alOFa8cyN9xfqaLK"
          + "1TvYVQHZfOcVvgM5XztCEOPNcQ5AWMJmTOESwvjuHkj5ulGt2jCVJUWKxPX-KYq0UFlb5jr305D66p5vRKb7z"
          + "BterpDJSOxwLKr7g9jVhgpM2mgVjrRnQPMUAfvt8q9QMUWy1eIgIxnABi9b28cZ6WBDi42LMYiHz8mfUWi_ga"
          + "9TASAwTqYZmGFUr7Z71ZuPKxuOxsgTxUksqKEmJw8iWcCgTC6-O8sMe-aZ3gqcwDEk9kRKZQJKlxtyYuArn2z"
          + "DKfaAHJ1A2wLwjtq8m_TsiOEdW3289Fe_F4gSA_wIDAQAB";

  @SuppressWarnings("SpellCheckingInspection")
  private static final String EDDSA_RAW_KEY = "3wIKsJK63Ctb-nLkcwG8fJOp2vZxz8lmhv3BcFI-ves";

  @SuppressWarnings("SpellCheckingInspection")
  public static final String EDDSA_SPKI =
      "MCowBQYDK2VwAyEA3wIKsJK63Ctb-nLkcwG8fJOp2vZxz8lmhv3BcFI-ves";

  /** ES256 (SECP256R1) key. A fresh map each call, so callers may mutate it freely. */
  public static Map<Integer, Object> es256() {
    return ec2Key(-7, 1, Base64.fromUrlSafeString(ES256_X), Base64.fromUrlSafeString(ES256_Y));
  }

  /** ES384 (SECP384R1) key. */
  public static Map<Integer, Object> es384() {
    return ec2Key(-35, 2, Base64.fromUrlSafeString(ES384_X), Base64.fromUrlSafeString(ES384_Y));
  }

  /** ES512 (SECP521R1) key. */
  public static Map<Integer, Object> es512() {
    return ec2Key(-36, 3, Base64.fromUrlSafeString(ES512_X), Base64.fromUrlSafeString(ES512_Y));
  }

  /** RS256 key. */
  public static Map<Integer, Object> rs256() {
    Map<Integer, Object> cose = new HashMap<>();
    cose.put(1, 3); // kty: RSA
    cose.put(3, -257); // alg
    cose.put(-1, Base64.fromUrlSafeString(RS256_N)); // n
    cose.put(-2, Base64.fromUrlSafeString(RS256_E)); // e
    return cose;
  }

  /** EdDSA (Ed25519) key. */
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

  // ---------------------------------------------------------------------------------------------
  // Regression vectors — see the class comment.
  // ---------------------------------------------------------------------------------------------

  /** A COSE EC2 public key and the SPKI encoding a correct decoder must produce for it. */
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

  /** SECP256R1, x begins 0xFF 0x9F: the leading byte is redundant and gets truncated away. */
  public static final Vector ES256_TRUNCATING_X =
      new Vector(
          -7,
          1,
          "ff9f4aa102ef0ff733e9f8c4e5e6df114596d6c94ad81ac237b0ef9ef004ee81",
          "238b7bfb3be7c9be1af55766343a0c7022fe93b9bf9a44d2a694cef7900dbfce",
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE_59KoQLvD_cz6fjE5ebfEUWW1slK2BrCN7DvnvAE7oEji3v7O-fJ"
              + "vhr1V2Y0OgxwIv6Tub-aRNKmlM73kA2_zg");

  /** SECP256R1, y begins 0xFF 0xA0: x and y are decoded separately, so both need covering. */
  public static final Vector ES256_TRUNCATING_Y =
      new Vector(
          -7,
          1,
          "edc4254f9e0612569c4be857c7d09a60cd4555e867909c76471cb2ed420cd819",
          "ffa06b06845c31ec9b81bc4ca122ed16b083f7e9d263bc475e864937171cecfe",
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7cQlT54GElacS-hXx9CaYM1FVehnkJx2Rxyy7UIM2Bn_oGsGhFwx"
              + "7JuBvEyhIu0WsIP36dJjvEdehkk3Fxzs_g");

  /**
   * SECP384R1, x begins 0xFF 0xCF: shows the defect and the fix are independent of coordinate
   * width. A P-384 y case would add no new path, being the same curve as this vector and the same
   * coordinate role as {@link #ES256_TRUNCATING_Y}.
   */
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

  /**
   * Boundary case. SECP256R1 with x beginning 0xFF 0x22: the leading 0xFF is <em>not</em>
   * redundant, so the minimal form keeps its width and this decodes correctly even under signed
   * decoding. It is here so that a fix for the vectors above cannot regress it by stripping or
   * padding unconditionally.
   */
  public static final Vector ES256_LEADING_FF =
      new Vector(
          -7,
          1,
          "ff229b98c9e2fbdc6b5b80a7aa28f671d6ffc7444f069bb1c9f4c3a13b0610f9",
          "e6593b7734faaa4aa0db2934b3df4a91bfb3f221c986b4add02665720b321023",
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE_yKbmMni-9xrW4Cnqij2cdb_x0RPBpuxyfTDoTsGEPnmWTt3NPqq"
              + "SqDbKTSz30qRv7PyIcmGtK3QJmVyCzIQIw");

  /**
   * Asserts that {@link Cose#getPublicKey} round-trips the vector's coordinates exactly: the affine
   * coordinates of the returned key must equal the unsigned values that went in, and the SPKI
   * encoding must match the independently computed expectation.
   *
   * <p>Asserting on the affine coordinates as well as the encoding matters, because a provider that
   * accepts an off-curve point fails silently rather than throwing.
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

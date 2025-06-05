/*
 * Copyright (C) 2020-2024 Yubico.
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
package com.yubico.yubikit.testing.piv;

import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.piv.KeyType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Assert;

@SuppressWarnings("SpellCheckingInspection")
public class PivTestUtils {

  private static final SecureRandom secureRandom = new SecureRandom();

  private enum StaticKey {
    RSA1024(
        KeyType.RSA1024,
        "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALWeZ0E5O2l_iHfck9mokf1iWH2eZDWQoJoQKUOAe"
            + "VoKUecNp250J5tL3EHONqWoF6VLO-B-6jTET4Iz97BeUj7gOJHmEw-nqFfguTVmNeeiZ711TNYNpF7kwW7y"
            + "WghWG-Q7iQEoMXfY3x4BL33H2gKRWtMHK66GJViL1l9s3qDXAgMBAAECgYBO753pFzrfS3LAxbns6_snqcr"
            + "ULjdXoJhs3YFRuVEE9V9LkP-oXguoz3vXjgzqSvib-ur3U7HvZTM5X-TTXutXdQ5CyORLLtXEZcyCKQI9ih"
            + "H5fSNJRWRbJ3xe-xi5NANRkRDkro7tm4a5ZD4PYvO4r29yVB5PXlMkOTLoxNSwwQJBAN5lW93Agi9Ge5B2-"
            + "B2EnKSlUvj0-jJBkHYAFTiHyTZVEj6baeHBvJklhVczpWvTXb6Nr8cjAKVshFbdQoBwHmkCQQDRD7djZGIW"
            + "H1Lz0rkL01nDj4z4QYMgUs3AQhnrXPBjEgNzphtJ2u7QrCSOBQQHlmAPBDJ_MTxFJMzDIJGDA10_AkATJjE"
            + "Zz_ilr3D2SHgmuoNuXdneG-HrL-ALeQhavL5jkkGm6GTejnr5yNRJZOYKecGppbOL9wSYOdbPT-_o9T55Ak"
            + "ATXCY6cRBYRhxTcf8q5i6Y2pFOaBqxgpmFJVnrHtcwBXoGWqqKQ1j8QAS-lh5SaY2JtnTKrI-NQ6Qmqbxv6"
            + "n7XAkBkhLO7pplInVh2WjqXOV4ZAoOAAJlfpG5-z6mWzCZ9-286OJQLr6OVVQMcYExUO9yVocZQX-4XqEIF"
            + "0qAB7m31",
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1nmdBOTtpf4h33JPZqJH9Ylh9nmQ1kKCaEClDgHlaClHnDadud"
            + "CebS9xBzjalqBelSzvgfuo0xE-CM_ewXlI-4DiR5hMPp6hX4Lk1ZjXnome9dUzWDaRe5MFu8loIVhvkO4kB"
            + "KDF32N8eAS99x9oCkVrTByuuhiVYi9ZfbN6g1wIDAQAB"),
    RSA2048(
        KeyType.RSA2048,
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0G266KNssenUQwsqN3-f3ysmiHgp4345wsaiDc"
            + "xXryXX3pXr3vYdiJFQ6HiiMbfdpm4FeulLYCOdBghKHIh_MnxTuwq6mPrxzLFxqGfHinvORc4Y-mZSiicN_"
            + "Ajo-uQdgH5LrhlHJ0g7ae26RWW3Z4pOel_SeXWJgKm4prhKzi6Or3NZ1l4Wpg4C_lrLD9_bhL6XdUmr_kXc"
            + "2UoldUz1ZyTNmDqr0oyix52jX-Tpxp7WsPUmXUoapxVpugOQKlkCGFltb5jnaK8VYrlBfN0a7N0o-HCSITh"
            + "jBLbr65qKXOmUYgS-q5OmidyeCz_1AJ5OLwSf63M71NXMtZoJjLdMBAgMBAAECggEAT6Z-HnfpDc-OK_5pQ"
            + "7sMxCn7Z-WvLet3--ClrJRd0mvC7uVQ73TzBXUZhqZFumz7aMnrua_e6UlutCrI9NgjhgOoZzrTsBO4lZq9"
            + "t_KHZXh0MRQM_2w-Lm-MdIPQrGJ5n4n3GI_LZdyu0vKZYFBTY3NvY0jCVrLnya2aEHa6MIpHsDyJa0EpjZR"
            + "MHscPAP4C9h0EE_kXdFuu8Q4I-RUhnWAEAox9wGq05cbWAnzz6f5WWWHUL2CfPvSLHx7jjCXOmXf035pj91"
            + "IfHghVoQyU0UW29xKSqfJv7nJwqV67C0cbkd2MeNARiFi7z4kp6ziLU6gPeLQq3iyWy35hTYPl3QKBgQDdl"
            + "znGc4YkeomH3W22nHol3BUL96gOrBSZnziNM19hvKQLkRhyIlikQaS7RWlzKbKtDTFhPDixWhKEHDWZ1DRs"
            + "9th8LLZHXMP-oUyJPkFCX28syP7D4cpXNMbRk5yJXcuF72sYMs4dldjUQVa29DaEDkaVFOEAdIVOPNmvmE7"
            + "MDwKBgQDQEyImwRkHzpp-IAFqhy06DJpmlnOlkD0AhrDAT-EpXTwJssZK8DHcwMhEQbBt-3jXjIXLdko0bR"
            + "9UUKIpviyF3TZg7IGlMCT4XSs_UlWUct2n9QRrIV5ivRN5-tZZr4-mxbm5d7aa73oQuZl70d5mn6P4y5OsE"
            + "c5sXFNwUSCf7wKBgDo5NhES4bhMCj8My3sj-mRgQ5d1Z08ToAYNdAqF6RYBPwlbApVauPfP17ztLBv6ZNxb"
            + "jxIBhNP02tCjqOHWhD_tTEy0YuC1WzpYn4egN_18nfWiim5lsYjgcS04H_VoE8YJdpZRIx9a9DIxSNuhp4F"
            + "jTuB1L_mypCQ-kOQ2nN25AoGBAJlw0qlzkorQT9ucrI6rWq3JJ39piaTZRjMCIIvhHDENwT2BqXsPwCWDwO"
            + "uc6Ydhf86soOnWtIgOxKC_yaYwyNJ6vCQjpMN1Sn4g7siGZffP8Sdvpy99bwYvWpKEaNfAgJXCj-B2qKF-4"
            + "iw9QjMuI-zX4uqQ7bhhdTExsJJOMVnfAoGABSbxwvLPglJ6cpoqyGL5Ihg1LS4qog29HVmnX4o_HLXtTCO1"
            + "69yQP5lBWIGRO_yUcgouglJpeikcJSPJROWPLs4b2aPv5hhSx47MGZbVAIhSbls5zOZXDZm4wdfQE5J-4kA"
            + "VlYF73ZCrH24ZbqqyMF_0wDt_NExsv6FMUwSKfyY=",
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtBtuuijbLHp1EMLKjd_n98rJoh4KeN-OcLGog3MV68l19"
            + "6V6972HYiRUOh4ojG33aZuBXrpS2AjnQYIShyIfzJ8U7sKupj68cyxcahnx4p7zkXOGPpmUoonDfwI6PrkH"
            + "YB-S64ZRydIO2ntukVlt2eKTnpf0nl1iYCpuKa4Ss4ujq9zWdZeFqYOAv5ayw_f24S-l3VJq_5F3NlKJXVM"
            + "9WckzZg6q9KMosedo1_k6cae1rD1Jl1KGqcVaboDkCpZAhhZbW-Y52ivFWK5QXzdGuzdKPhwkiE4YwS26-u"
            + "ailzplGIEvquTponcngs_9QCeTi8En-tzO9TVzLWaCYy3TAQIDAQAB"),
    RSA3072(
        KeyType.RSA3072,
        "MIIG_QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQCe4Vci7OxOOxek5ZJ_A7uklWpkiRvwAqguotUwD"
            + "wXybJqvz2sf0TMgYbSweBLrnt253-w_cJUkXeRS6JgYJNPM5R7ztaWL8Jsl3ETZVwpWJYZ9cRXmI71kB3ys"
            + "0ROQwP8Srqw0vT3R6d8DOJ6SbQveScG4Bu5QG_OpFvfwS9qxv7OJGVbTV1w5lPBzQGZ4AFz0annGgz2FVZ6"
            + "q61LgabJfjMygxWPNQjbY8HdrsGz3T8RMjb3rRhNKxlZmVZob3qGpHxcDqvWMSz9aPgSzFTBWyIKv16_rzM"
            + "JWcISfm-Ye_jpRAFV1quKHau7XPJJoMDdOF0FPyJSLckt97aRjGBG88OwdW-Aj8xMA25_Zrx4Ja_SmHTBX4"
            + "RGQJgM4qwhZV-XeHfNX5uML0tZgMIi6PzzbXaF6VIpDF7DsQEkMNheSXcWoD7Mf_gHS_coj0DP8VEuaEd_u"
            + "-L4EvJHrbfVZ1cwhlIlhE7MrfkqKWZArypLarrZ7V7shU5pZZe0GEQkc6i0CAwEAAQKCAYALPBd_jH3cPVD"
            + "7c9FjYmXxKjCjCc_8LY_rdk-5bYKH5TaeAn6Kei5Rlp8ikGcUGsCGjYdE6CbfsrT7yN9Ca84_UZ9Z7-kUJ3"
            + "AtIfGLZdyBAXfMZIP-KV5R1bay-LjXtlIDJe9e7lfSAWXn8ifCZmwdrJ0CcJkG-KcG-K0RJKgDBDGDmxNY7"
            + "_dBSh8jozTrvOjVzrasOykNRePppajPXiIDIC9zGeooAEvlFMH5DzlxVoZkvGwm2CZylepTo695U4mB6Fbz"
            + "GxHDCXjYVAsQDULx-j670TjnWkmuqXNGEN_SGgAdsEA51gJv8ar1at3nJf2LleSYNAL6sHOski9uEYXJ3Ca"
            + "cWvnZRzT_YNT7WKujhmIS3EwOZgbrYI3QreOls9Vy-Xo53oCwiAii5zvxDMkZmG6oOgblRsV4slXtNEaL1m"
            + "N2vM2_a4_Kg_yRmzFMY9znYp46qDj5QbmQ5MhEKgC-_DOrX0ih09eNlrgK6nb9VxlI046zthxY3beq47Z59"
            + "mkCgcEAy0KHoX4vA-llBohsGiB_mCa6vvpdYk-uKqUcnEBG9u7UFEXKFn3n7ern2v6D1Om69u4S4_PIw2uS"
            + "MBZ89jhNpo2WbX5GI_zQ-DCct9HJEN7vHM9W9AVuWLdn6_HM8PzTvrke1ZKGXorug-IWww6uaaBj-9rHJTT"
            + "q_Bg0oUk1jv2jianp2Ct5ScFm4--kIjmb1AuLebywCvMSxZ5VtYHfb4VRgCM-nAIOdv9s27FNkyVKHCgjK0"
            + "dkLCMB0DgoTjGlAoHBAMga6ETh49iQtCAJpq28cQnqLSOCUI7dLqJcnEitUL5PtyCFkrpS7ZfLr15cHi4Ud"
            + "9ycxtbaxAlaNtLo31l8tpLgbeVck0Ke67OUMRGrq9ONVXTYMNNX3tq2M7XO2slKa82O_tUDMjVlVv6v7R-L"
            + "XTeqXItgxdISg-ZAYQHG550n6Ldterc2WxGOFZNjD1fkgbdwnu9f9DT-jS-m_C_oGXD5iqAaV2ovcVFb19i"
            + "ubRrltcqDi1nyhXnyKyjYNXff6QKBwQCBdsPLAgNSO4PEkHpCffanY-vIntGCP_xQX1CE2ZAZ0m805mrcvp"
            + "9OdDPv0fMIV0Nl6qgPl4SFrGu1w20eqygScNaisS5d17cGjngTwUSPQWAN-qaI0TjCuzcvGpmN2YvJTEIui"
            + "KCbcWSQjh4vaZd_4dAtZ-E2eqk9nvFO1cGObVGP6rDupmofp1cw0b-6qPTvL9dL1_pNTxvi0YIIFUvKzaDm"
            + "vAwx9EFgXDrrB9jAY5z7qDkWZOeSEU4jYNGTVJ0CgcBlfTgmj4b29NVWlm6CGVwfkjTYmKRxAP9A-8WMGtM"
            + "j4txXU0fK1nqIjZbhPclUx67PJni2yfe5YpcBu3hkM5uJvOgf9yb9GAslZljIxI_-WOVpwKhq2FtABD8Py9"
            + "0tUGCCvi7DLL7PVBmeTO3wHMfnjrEnQ6qxVBCvvCE3PIGGNJKUTaN6vsfLjIum2AwVIOElf6oscDc0lZJYA"
            + "9JOHeKhaP8FGrcRNQS9Jd7AmB7gEHd2QedwdE98PPXk3lun89kCgcATb1Hcac_ASVlLfyNvhEWYS7yHfALv"
            + "GlCSTv-zdsIhnZ0oeN8ILSmzM0QaRB6matSnt-ocYJmJYuVwuzHFwZ-eitjnEmVMuMAMykUV40flaATPqER"
            + "ZvJmVmZbbCBv5qdb48zFkXQtR4qUSvg6GjGUL7CAlBEjqW479l3KtiUuUF7WlIfU-iHhbA7HfkSbN8gtTor"
            + "X5_t3OwZeFf-OGki5Iaf92uoq716yEBvD45dbPnkJG5sQTWDIHIKmRcwQ9ibw=",
        "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAnuFXIuzsTjsXpOWSfwO7pJVqZIkb8AKoLqLVMA8F8myar"
            + "89rH9EzIGG0sHgS657dud_sP3CVJF3kUuiYGCTTzOUe87Wli_CbJdxE2VcKViWGfXEV5iO9ZAd8rNETkMD_"
            + "Eq6sNL090enfAziekm0L3knBuAbuUBvzqRb38Evasb-ziRlW01dcOZTwc0BmeABc9Gp5xoM9hVWequtS4Gm"
            + "yX4zMoMVjzUI22PB3a7Bs90_ETI2960YTSsZWZlWaG96hqR8XA6r1jEs_Wj4EsxUwVsiCr9ev68zCVnCEn5"
            + "vmHv46UQBVdarih2ru1zySaDA3ThdBT8iUi3JLfe2kYxgRvPDsHVvgI_MTANuf2a8eCWv0ph0wV-ERkCYDO"
            + "KsIWVfl3h3zV-bjC9LWYDCIuj88212helSKQxew7EBJDDYXkl3FqA-zH_4B0v3KI9Az_FRLmhHf7vi-BLyR"
            + "6231WdXMIZSJYROzK35KilmQK8qS2q62e1e7IVOaWWXtBhEJHOotAgMBAAE="),
    RSA4096(
        KeyType.RSA4096,
        "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDLqdGZtBymZ0yzMPApteDlEc0hejP3Vee7i9L8V"
            + "23HytZyQak6RrlsDPSLgpkn3p9IUZ6fpMN6ND5TPCvYiGu69Um1MUHlE9n3iZEPLHzu1EhgUHpZMlqAwJYP"
            + "q1B_CA1yuiyjdafvb8t9CkKeVIg-ud9WZyQDc-NK1tneOpx87fKZaoqhrUoG4RySv3NwPJYiNgjIIzfZiNZ"
            + "5hyGHzTV3zi8bXt7Qt-pzIDn0QBciWHHpxGBGpxdQ74xu0K2mctwsnmJSi69FqNWhKekby0M-ZmBRw5d92Z"
            + "fOWbYOslSUmI2dyDvNvojyNDPUFeWq1T8OaMYoAKe-CvXupZpLSGTzgDUZ23kG5aiKFYCiePGBeeYdhCuZq"
            + "_ybwM0CI-kCfmfZW1L2o-nZshTuSJxpnTcOVwzX_fkFVlN5dLwXCwLxhJNTJ7Vi5NnzS4Yp8NfY9iPkD97m"
            + "76zLOMfInt50qhxoyEjRK_r-Afjcv-hzrqyp9Q_dontQMVM-y0ck1MKhwl7N4-3k29hy_T9OfTF7qpV02RF"
            + "36kVEeHZBLZN6ZlEkA89rib_IUj7wM6qWH3_m3NAELPCUhQ7jCBmnCzTssElwwYqy7jbpmImdWq6JCRyIv_"
            + "LUubGYmrUrYKpEfNKTMHjGMhNdOJlkjwDZZqlPl6KvNcKe8xibAkHn1KCQxBH0SwIDAQABAoICAEaKicY2m"
            + "8vJMMhKFY0k6YH-EfJb_N7Y2txbWFc9wxD2ASPu-TntoDC8JgGiWQD1u27Vkl8SNwC_Uq0KxNcJnWLSrdZ7"
            + "-qppH1B9TgiW7KjeTzlI9q-pYK6CxhckS8vMErhforF1QZcNvkoPgTaM6ensAF7Rd6hYfewAkdLGs0gUNLi"
            + "NrfnE50SNuRNdC5Ne8NNlqtIDXMdUfZD3TJZYbgISoL9Ws09QvHxmt5wRjNHBF6eT9JLUMh--8QG69sKVuw"
            + "wbScv0hN9YVLIvLYYKd76HwCnh2Llm4g0_hm79to0Hb9msLoabTZyylxcJBJUQqngHs0bMv0z0R-2CX3he2"
            + "VPdrfrXEpX3UCpNu-BCmXxNNlfB65o8NtG_ro77RZrMAhMnr1H2Xrj-FdTE-Q5gs5oOqp21wThoZs9SjDF1"
            + "S6SiOyES47EfRE1a8gVTCAC7HAgtLNauj4ik_qDTuah1ucUrgqu3f2ZaqWKxSVlYgewPPu9Xuwxgh2h0zv0"
            + "a1dhT7OA7OC_Wn63KNgN7W2tr2CLNG5jWY7L723nVnJjorWmc2FynpOhi6k2IQoJ-DPVpKpttAI6f-rCvAI"
            + "uPe_EIyKG1Pu_Em0To796_QLY-VstJoYscZwBd2ZH6ZTr1bwNSWHkp5nR9k05u108-WD03wtip6cl8-iGca"
            + "IpqI67Oo-bdAoIBAQDnX-RxftNxrMjiOF54Qtj-9Qt25lR72C74s5aJCsci0jCBnhGyvrIQPYTufvgo5m2m"
            + "qyEKjVJcOfprN9VpL3gZjfaDAq6Vl5WE6-Q-cxF2B9rpX9Tuzo4Fmj83ReElidel9w7am4U3TbToyZ1h0pS"
            + "OJftr3BhnmMcOlOIiaplDawJ6THb03lkvV5JAwiAZR64TPGNv3njhkr295Hn1kIhMetZSzPGnEfbAbRmfhw"
            + "FLfobcE5xdIlK2EhpJdMS5ovKINVA6Fw2xEEaC6CYn4xPkVJTPafGVK8TZZie-QFkAVsIk311oiftMiMK1K"
            + "57d5RcE1hdXSdYUFpeVYmI30OT3AoIBAQDhVuWzt8wGkg7ZVwc_4VMd0cT1qA_XMCvQ4wl6mIMITLUYXFEj"
            + "kpFnLSntkAy34tGTPOqpM9DeCbumtjj3HPd893ERNEkxlpfR2oY9L4XM6fQajCGxIbv5H1cLnsblJa_P5cK"
            + "tRjYWqrY4adU2qOrX6VGaJkvckJC3BjO4xGNlvRE_y-xfmShwQEfW7L8ehgdEhb8_F14GbpyFz7ZzD4nGon"
            + "ecQwdkAsBBEgwPSnVF-4d7R3J1GwyGrtDHSEdaRsL_S-O3HkepPADApntAIGVUR_MI_mCtmsUtc_5mUqg-b"
            + "JQqh5dnFsIwXZLZQyQaVvewPUedkkHgXn54_s0h5BpNAoIBAQCByT6Bk5zUFRISI4CKgSTrz1UA-y7E0X13"
            + "sHVupgcSN0lSS_Kti16i0X9xsPNPLgKwDSpZmvBqH3OjFQy3FhOOch2nW6fG7eLHTvMXPMC8rqdTZZgx5Ne"
            + "xuNZhEOe8gNfglvdUFQzi-snSEtYfe1otaozf8fQWmJKAUW-P0q_qK2qWY7IOpXLtpXe6r6oFxDmXPLail-"
            + "7Cyed5T2JCJzLtg7IZfDDJgMAjLI_E9pv5Vx4a8T0y2QAAdaMdNUzsvMTDNvSrwSbC_dgvsj1E_pG38OIQf"
            + "uMuxACF2lHM3JeQIxqASHNDIrM-OTDPI4rX-Zux8M3i_t4BIrMg7rEdkiX9AoIBACapLgfDhPGrpXiMgeXn"
            + "1sbK8qvjBbS5wwq3qSyrde-6mWdwj0s3HlNBYGwtxsDV3XcRgIE_LpqpuNRFd0iOY7fBDFkTS2uCltGeWGG"
            + "vAZnCmerkF_O4AfQf-GM5_o3aBWv504i-_xCsgU70eWxDVudsVF_KKkHRW8LLAZy1tQgDhC4Z4pgUQuffX3"
            + "P0cmXeQOj0uXctnygjWh9rH7Zl-BFoVnUs2tvBzRJc8ky9TZmQKhJwk6ab2W5SF-fY8sT-Vv5OGueT_l9-t"
            + "_JVndfGtxvarEviuNuQLjw6Jm-PxuXO4yzYzpUVRoPdyhAUgOE0ApLuMJdMPJkuHSzNKoyiAhECggEBAJgn"
            + "1SBkJqfa6cgx7W2eEn8kp4wBpIuPjkFzJcJJ7LBbfmzCMKX8SBZRcF2kOIOuM8TCFxkW5q8wRUTeqP2awgA"
            + "MnYWeuxhJM0rzbVg3l6I1Lr1HIOxEExxERr11Qtz3tXM6I2UVJyEF4hu3P1CsZeXJp8458jySwhC4J0Tir5"
            + "sQ8fj2M0wOiwHYXDY1A01EpicaeFv7882RHdlPUXXyHORvZ6vA8IVga_PyUovzmvmueOFp2HFmoqpPLbtiz"
            + "8UgfYVsAyGAPiJpTOXT2YipLMeUb7MXdAon100pIxjrfatE7iJRs6jW0o4tM7ctAhZ7IXQWuolas4ly8L0M"
            + "ABx9258=",
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy6nRmbQcpmdMszDwKbXg5RHNIXoz91Xnu4vS_Fdtx8rWc"
            + "kGpOka5bAz0i4KZJ96fSFGen6TDejQ-Uzwr2IhruvVJtTFB5RPZ94mRDyx87tRIYFB6WTJagMCWD6tQfwgN"
            + "croso3Wn72_LfQpCnlSIPrnfVmckA3PjStbZ3jqcfO3ymWqKoa1KBuEckr9zcDyWIjYIyCM32YjWeYchh80"
            + "1d84vG17e0LfqcyA59EAXIlhx6cRgRqcXUO-MbtCtpnLcLJ5iUouvRajVoSnpG8tDPmZgUcOXfdmXzlm2Dr"
            + "JUlJiNncg7zb6I8jQz1BXlqtU_DmjGKACnvgr17qWaS0hk84A1Gdt5BuWoihWAonjxgXnmHYQrmav8m8DNA"
            + "iPpAn5n2VtS9qPp2bIU7kicaZ03DlcM1_35BVZTeXS8FwsC8YSTUye1YuTZ80uGKfDX2PYj5A_e5u-syzjH"
            + "yJ7edKocaMhI0Sv6_gH43L_oc66sqfUP3aJ7UDFTPstHJNTCocJezePt5NvYcv0_Tn0xe6qVdNkRd-pFRHh"
            + "2QS2TemZRJAPPa4m_yFI-8DOqlh9_5tzQBCzwlIUO4wgZpws07LBJcMGKsu426ZiJnVquiQkciL_y1LmxmJ"
            + "q1K2CqRHzSkzB4xjITXTiZZI8A2WapT5eirzXCnvMYmwJB59SgkMQR9EsCAwEAAQ=="),
    ECCP256(
        KeyType.ECCP256,
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaEygF-BBlaq6MkmJuN4CTGYo2QPJZYadPjRhKPodC"
            + "dyhRANCAAQA9NDknDc4Mor6mWKaW0zo3BLSwF8d1yNf4HCLn_zbwvEkjuXo7-tob8faiZrixXoK7zuxip8y"
            + "h86r-f0x1bFG",
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAPTQ5Jw3ODKK-plimltM6NwS0sBfHdcjX-Bwi5_828LxJI7l6O_ra"
            + "G_H2oma4sV6Cu87sYqfMofOq_n9MdWxRg"),
    ECCP384(
        KeyType.ECCP384,
        "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCqCSz-IHpchR9ffO4TJKkxNiBg5Wlg2AK7u4ge_egQZ"
            + "C_qQdTxFZZp8wTHDMNzeaOhZANiAAQ9p9ePq4YY_MfPRQUfx_OPxi1Ch6e4uIhgVYRUJYgW_kfZhyGRqlEn"
            + "xXxbdBiCigPDHTWg0botpzmhGWfAmQ63v_2gluvB1sepqojTTzKlvkGLYui_UZR0GVzyM1KSMww",
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPafXj6uGGPzHz0UFH8fzj8YtQoenuLiIYFWEVCWIFv5H2YchkapRJ8V8W"
            + "3QYgooDwx01oNG6Lac5oRlnwJkOt7_9oJbrwdbHqaqI008ypb5Bi2Lov1GUdBlc8jNSkjMM"),
    ED25519(
        KeyType.ED25519,
        "MC4CAQAwBQYDK2VwBCIEIO_yEBZ291rK6lY8BH3RVtO61LnzLv78VxVxBZDj3uvi",
        "MCowBQYDK2VwAyEA7m2UD-6mR8vVSpGFFYCnsDgXTuFRT5_M7yVOMM_7uHw="),
    X25519(
        KeyType.X25519,
        "MC4CAQAwBQYDK2VuBCIEIJjvGxF_sesDPC6uoIanoMQU-O4HGMpCqyBssnhc8yBS",
        "MCowBQYDK2VuAyEAq6Ws-klOFZ_Kbnf4TPqR45T9szGWeKz-5udDURxOeS4");

    private final KeyType keyType;
    private final String privateKey;
    private final String publicKey;

    StaticKey(KeyType keyType, String privateKey, String publicKey) {
      this.keyType = keyType;
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    }

    private KeyPair getKeyPair() {
      try {
        KeyFactory kf =
            KeyFactory.getInstance(
                (keyType == KeyType.ED25519 || keyType == KeyType.X25519)
                    ? keyType.name()
                    : keyType.params.algorithm.name());
        return new KeyPair(
            kf.generatePublic(new X509EncodedKeySpec(Base64.fromUrlSafeString(publicKey))),
            kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.fromUrlSafeString(privateKey))));
      } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
        throw new IllegalStateException(e);
      }
    }
  }

  private static final String[] EC_SIGNATURE_ALGORITHMS =
      new String[] {
        "NONEwithECDSA",
        "SHA1withECDSA",
        "SHA224withECDSA",
        "SHA256withECDSA",
        "SHA384withECDSA",
        "SHA512withECDSA"
      };
  private static final String[] RSA_SIGNATURE_ALGORITHMS =
      new String[] {
        "NONEwithRSA",
        "MD5withRSA",
        "SHA1withRSA",
        "SHA224withRSA",
        "SHA256withRSA",
        "SHA384withRSA",
        "SHA512withRSA"
      };
  private static final String[] RSA_CIPHER_ALGORITHMS =
      new String[] {
        "RSA/ECB/PKCS1Padding",
        "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
      };

  public static KeyPair generateKey(KeyType keyType) {
    switch (keyType) {
      case ECCP256:
        return generateEcKey("secp256r1");
      case ECCP384:
        return generateEcKey("secp384r1");
      case ED25519:
        return generateCv25519Key("ED25519");
      case X25519:
        return generateCv25519Key("X25519");
      case RSA1024:
      case RSA2048:
      case RSA3072:
      case RSA4096:
        return generateRsaKey(keyType.params.bitLength);
    }
    throw new IllegalArgumentException("Invalid algorithm");
  }

  private static KeyPair generateEcKey(String curve) {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyType.Algorithm.EC.name());
      kpg.initialize(new ECGenParameterSpec(curve), secureRandom);
      return kpg.generateKeyPair();
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      throw new IllegalStateException(e);
    }
  }

  private static KeyPair generateCv25519Key(String keyType) {
    if (!Objects.equals(keyType, "ED25519") && !Objects.equals(keyType, "X25519")) {
      throw new IllegalArgumentException("Invalid key keyType");
    }
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyType);
      return kpg.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static KeyPair generateRsaKey(int keySize) {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyType.Algorithm.RSA.name());
      kpg.initialize(keySize);
      return kpg.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  public static KeyPair loadKey(KeyType keyType) {
    for (StaticKey staticKey : StaticKey.values()) {
      if (keyType == staticKey.keyType) {
        return staticKey.getKeyPair();
      }
    }
    throw new IllegalArgumentException("Unknown algorithm");
  }

  public static X509Certificate createCertificate(KeyPair keyPair)
      throws IOException, CertificateException {
    X500Name name = new X500Name("CN=Example");
    X509v3CertificateBuilder serverCertGen =
        new X509v3CertificateBuilder(
            name,
            new BigInteger("123456789"),
            new Date(),
            new Date(),
            name,
            SubjectPublicKeyInfo.getInstance(
                ASN1Sequence.getInstance(keyPair.getPublic().getEncoded())));

    String algorithm;
    KeyType keyType = KeyType.fromKey(keyPair.getPrivate());
    switch (keyType.params.algorithm) {
      case EC:
        algorithm = keyType == KeyType.ED25519 ? "ED25519" : "SHA256WithECDSA";
        break;
      case RSA:
        algorithm = "SHA256WithRSA";
        break;
      default:
        throw new IllegalStateException();
    }
    try {

      // for X25519 we sign with a temporary key
      PrivateKey pk = null;
      if (keyType == KeyType.X25519) {
        try {
          KeyPairGenerator kpg = KeyPairGenerator.getInstance("ED25519");
          kpg.initialize(255);
          KeyPair tempKeyPair = kpg.generateKeyPair();
          pk = tempKeyPair.getPrivate();
          algorithm = "ED25519";
        } catch (Exception e) {
          // ignored
        }
      } else {
        pk = keyPair.getPrivate();
      }

      ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(pk);
      X509CertificateHolder holder = serverCertGen.build(contentSigner);

      InputStream stream = new ByteArrayInputStream(holder.getEncoded());
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(stream);
    } catch (OperatorCreationException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] sign(PrivateKey privateKey, Signature algorithm) throws Exception {
    byte[] message = "Hello world".getBytes(StandardCharsets.UTF_8);
    algorithm.initSign(privateKey);
    algorithm.update(message);
    return algorithm.sign();
  }

  public static void verify(PublicKey publicKey, Signature algorithm, byte[] signature)
      throws Exception {
    byte[] message = "Hello world".getBytes(StandardCharsets.UTF_8);
    algorithm.initVerify(publicKey);
    algorithm.update(message);
    boolean result = algorithm.verify(signature);
    Assert.assertTrue("Signature mismatch for " + algorithm.getAlgorithm(), result);
  }

  public static void rsaSignAndVerify(PrivateKey privateKey, PublicKey publicKey) throws Exception {
    for (String algorithm : RSA_SIGNATURE_ALGORITHMS) {
      verify(
          publicKey,
          Signature.getInstance(algorithm),
          sign(privateKey, Signature.getInstance(algorithm)));
    }
  }

  public static void encryptAndDecrypt(PrivateKey privateKey, PublicKey publicKey, Cipher algorithm)
      throws Exception {
    byte[] message = "Hello world".getBytes(StandardCharsets.UTF_8);

    algorithm.init(Cipher.ENCRYPT_MODE, publicKey);
    byte[] encrypted = algorithm.doFinal(message);

    algorithm = Cipher.getInstance(algorithm.getAlgorithm());
    algorithm.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] decrypted = algorithm.doFinal(encrypted);

    Assert.assertArrayEquals("Decrypted mismatch", decrypted, message);
  }

  public static void rsaEncryptAndDecrypt(PrivateKey privateKey, PublicKey publicKey)
      throws Exception {
    for (String algorithm : RSA_CIPHER_ALGORITHMS) {
      encryptAndDecrypt(privateKey, publicKey, Cipher.getInstance(algorithm));
    }
  }

  public static void rsaTests() throws Exception {
    for (KeyPair keyPair :
        new KeyPair[] {
          generateKey(KeyType.RSA1024),
          generateKey(KeyType.RSA2048),
          generateKey(KeyType.RSA3072),
          generateKey(KeyType.RSA4096)
        }) {
      rsaEncryptAndDecrypt(keyPair.getPrivate(), keyPair.getPublic());
      rsaSignAndVerify(keyPair.getPrivate(), keyPair.getPublic());
    }
  }

  public static void ecTests() throws Exception {
    for (KeyPair keyPair :
        new KeyPair[] {generateKey(KeyType.ECCP256), generateKey(KeyType.ECCP384)}) {
      ecSignAndVerify(keyPair.getPrivate(), keyPair.getPublic());
      ecKeyAgreement(keyPair.getPrivate(), keyPair.getPublic());
    }
  }

  public static void cv25519Tests() throws Exception {
    KeyPair ed25519KeyPair = generateKey(KeyType.ED25519);
    ed25519SignAndVerify(ed25519KeyPair.getPrivate(), ed25519KeyPair.getPublic());
  }

  public static void ecSignAndVerify(PrivateKey privateKey, PublicKey publicKey) throws Exception {
    for (String algorithm : EC_SIGNATURE_ALGORITHMS) {
      verify(
          publicKey,
          Signature.getInstance(algorithm),
          sign(privateKey, Signature.getInstance(algorithm)));
    }
  }

  public static void ed25519SignAndVerify(PrivateKey privateKey, PublicKey publicKey)
      throws Exception {
    String algorithm = "ED25519";
    verify(
        publicKey,
        Signature.getInstance(algorithm),
        sign(privateKey, Signature.getInstance(algorithm)));
  }

  public static void ecKeyAgreement(PrivateKey privateKey, PublicKey publicKey) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(((ECKey) publicKey).getParams());

    KeyPair peerPair = kpg.generateKeyPair();

    KeyAgreement ka = KeyAgreement.getInstance("ECDH");

    ka.init(privateKey);
    ka.doPhase(peerPair.getPublic(), true);
    byte[] secret = ka.generateSecret();

    ka = KeyAgreement.getInstance("ECDH");
    ka.init(peerPair.getPrivate());
    ka.doPhase(publicKey, true);
    byte[] peerSecret = ka.generateSecret();

    Assert.assertArrayEquals("Secret mismatch", secret, peerSecret);
  }

  public static void x25519KeyAgreement(PrivateKey privateKey, PublicKey publicKey)
      throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
    kpg.initialize(255);

    KeyPair peerPair = kpg.generateKeyPair();

    KeyAgreement ka = KeyAgreement.getInstance("X25519");

    ka.init(privateKey);
    ka.doPhase(peerPair.getPublic(), true);
    byte[] secret = ka.generateSecret();

    ka = KeyAgreement.getInstance("X25519");
    ka.init(peerPair.getPrivate());
    ka.doPhase(publicKey, true);
    byte[] peerSecret = ka.generateSecret();

    Assert.assertArrayEquals("Secret mismatch", secret, peerSecret);
  }
}

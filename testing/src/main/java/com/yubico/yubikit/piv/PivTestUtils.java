/*
 * Copyright (C) 2020-2026 Yubico.
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
package com.yubico.yubikit.piv;

import com.yubico.yubikit.core.internal.codec.Base64;
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
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
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
        "MCowBQYDK2VuAyEAq6Ws-klOFZ_Kbnf4TPqR45T9szGWeKz-5udDURxOeS4"),
    MLDSA44(
        KeyType.MLDSA44,
        "MIIKPgIBADALBglghkgBZQMEAxEEggoqMIIKJgQgyECmbYK0UHi8RV4f32-YcdWQJqAriJx_qw8mz_nW"
            + "-osEggoAXudLtj9To4o4EBeXL8sdOpyPOOYVgdga064sQjCa83atEwZ_R3_B8I31lTZlioG7EiXt06dp"
            + "cSXzl6k494-d9Nb7gq34EYoTbOMtOX_NV0PxVIcw0mM4LKdbmY8uO7k6GljRgd1-fdJPxM5VcVhvrMh8"
            + "vNq1rtFNlb6W0KYvzCxCEg2gwmiJAlBSMonkKEhRMFCKGJLhAJKgMExCskAZI5GJBArSqI2EsERMACGh"
            + "MGGJgkHiSE5BRI1UspFTImhMxhASOURgJiWIGEqTxJEItG3LGA1ioGzTCAqKuCgZpokgFQzLgIHDgFDU"
            + "Fo3kgG1QSE3JAEqAhBECuGHKkInESCoEBhACwY0buYUDw4hLRFDURiggIiwQAnKKOIoYw3AiBGSMEnJi"
            + "oAgJom0akgCRImnESHKixgxSOGKaCBFaGEWLAlATqXEcNQhZNIUgGYKhmJAaSCYSiU3agCASyEzUpICY"
            + "KELRIipAyCRIRCXgqIxAgixEMkWTQJGJlIkiIw3MQo4MoCgBNEKUokVhEEgKJCYJuDBikARUBnIYI4jg"
            + "QkRMQgghAILZIG0CEHJSBk2INoUIIw3iKIGhFEUgxgEcqIXMxoGBtEwSNIpAQG3YAiSJNoJbpomRFjJY"
            + "ICHiEiJkkowkRTASwFEZlgWZxghchkjKFoyURhEBOHEkE4IIqQnhyI1YknBIwGjBIoXjsmyhuAALNUYg"
            + "iYnZIiEcFYBcMHBANEiahIwBEIoRJlGERjJYGIoBkQ2gBE7QFkUKNgTCKIaJGAIZQCIZmWHLIGjgMA1i"
            + "IG4SxZDCuI1UmBDYOApKyHAAAkFQBCXLSJJjkogYJSgJF2ERoWEaNkJMREZjBoIMiFCRJk5ZCGYgMCjc"
            + "MGwbMEAMOQELQGjgNkaTOIqZSA6BiJFEBEngkCGSgCyKBIoBkC1IkGjZlmAaRVEUBSbQQkWDKCTJCCCk"
            + "QoqYMGqTCGYYKAKclI2QFlALMWRTlmgKQSVSIkqRtE0ZJEwgppBguIzKRomaNE2ToCSERg7IgE2TSEDB"
            + "kjFgsCQCF0UapnAUh5EMkA0gEUqJQmKMshALx4UARAoIBYQiBlAABSyjFnEaRkkUM23atgUhRWEgQAHh"
            + "hAyDRIIQtCGbRInIIkwAREmgBk5aIEoKtggDRYkYEjKIggzcgowMtGTgqCDbhEFMkATKxiyilGUKIyRE"
            + "QEHlmESmBTd2z4-0d5Jy1LZ0MoYcVcvauxrXWCoZhpdB5SccBMcy2P8IRGlxID-ISYMom5y85E84bBhm"
            + "wjGFcApz_hE_rlLiVSW8Y01eHit5t5GUB6ysP9xvDk8tIh6Bft6ED-dzREhSghZQymhs2kTZuz3erND9"
            + "T0KVBf19eZ4ttS6RHoZRHINj_4vSULr5no6QNa-CIrDAmmepLXs3-VLzI2snQjmBYo074R1ewuGnRDyU"
            + "97uWwEd33ujJ_cDDF98q41qmV3pvd9JGZY2jfRLRmTbZgbP_YhAta64HvieGq-XYrgK9apUvODR-HnFU"
            + "I_pkLILLTH0fAGvChNgKt5E-mxsup0NrdA1ar5E8KhPFhtwD_k-LiSdEvMZTn8iCVgmIb_hIloQeuEFx"
            + "2ciSuWkD2KA4KXXgi9o_r-qo7askPbNAjQhXAws9NrTupC3NXR_RDXmvzx_VBruzJOXoD-gkrDxBUhhJ"
            + "E4XdFSnbjlNpA5QJHj09brUyADIHta9pNsuV5mn-w4klj_fanwZeM-Jzr2_o7Q8haBIuz8G2HLPzaqUE"
            + "pb_GXbfgpNKwdCAuSMv_EhRYSe4zMv9Tzrr9l2Tccrrqtlg5s0uRN8CuI0_8ceCcj_fp1wbvRKT70_6C"
            + "yfQ0rrDy64BIbwyZPPbLxWr_xeL7TQAJMUy705j4j5wKXDQwW7v0hhfXhdAj0lEFhnxBWUUqHZ0pcfCV"
            + "RrbfHDCHCe9q4YRLSxPK1Vm0FvjKxrzNCwAjqVaf4Zc9sr8tutTbAe2CRNX7fP-Uv7SjxT5Lob9DUly6"
            + "TK6UgWMbuHji056V0eICgoCGkZ69m3naliCUftz_19OpDyiWheSxK5tt3BoByGtA-lfzxrYyoeksMm7s"
            + "KvbFpSGJYe_EhDNcBHjap8pQ7MdBao0JBrNHmcI5u3eWy-XKwI3u3LeYkA9y2Ix-Fls4cXWwK1WagFcM"
            + "lUMlHEbSiRe1t3KPxd01930OH53PSoZjw-wTxHXV8ZkdMv6DhckO6LUfmfhsUtmIvTUi4ZVABFlR65HS"
            + "jnYFbwi_Ox9HhEf0dLDqEytxTTctqm73Diw_WXWC8HluMdkbBw94CtBplxh7npDyNXpXNMCS0m1C8Ux0"
            + "p5yV5vFUJ3SjyDMFMWh2xmVJEuVz6MPT9wWZV44NzU4EmH8PuZ2caHY_-wu4FgUhHHxHispodn73S52S"
            + "D4XK2amjNFV1XtW23JwaZOCkPwtc1ZdEllNYzObUnITzi1RG_mwIXnmAo_S4J5wbCHJT2Pfd7sK1gRRJ"
            + "HkquDZSsz_IMOeIg4HkSB81DLMiB23uqrBwUcM40c49fGgVtaKbep-vR037SeZJwegqW1xD3zOaoskIo"
            + "W76EFJB7X25XnHH6JrGRgbLfBPYsaD7k_pPrcspsghuA8-kVK11qCb-_qdwgn2VhJUkIXv6KIkdzctAF"
            + "5gjO6E1LoO36d0vU3k9726DtiOnE4t86HI5q-NP0PujuS4_m8uun63wrI7oJBHLNuVOFXLshf94jqbx_"
            + "J-bS7gVsAZOnPvANXNI-bmhs6_Sf6SX3BYpvn7I7wCf0fy_Xrc2CJlfbUTdWuX_ASfhjCMrWqW1_MCLd"
            + "KH2LZJ-RcOBwKUffa6JkZPwDmVB31-9gTd1NSLmSATCn6uVixCCH6nA-s3sNvNzHX5_IgTb4LeOhcpua"
            + "mXfqofBL2KbmCmwKvk28Dd1IADCgWLwZeDbedeWEzprhrIWcHng8cfZP575YjNJegofo9tot3vCrTBmY"
            + "gSnCqBT3rATfBhhRQz4sRi9Vty_FRZ2jLGbjqnkLPUDon2uZ0BfTFly_UmoQ6aVwVtVgMkh_ntL_nIYi"
            + "WHO16MUG8m48_gMWszgs1MI2VUpIUCID21HsTyS3wLF2hYHXbcEjPIwy17Dz0zXBoD-r-OJ6aizC3TJA"
            + "nc7c2wx4BqRrW9UaroFpjxPbVQaou5XUx468Bj7STundbBNKl6ZKAxqzIYmf3K2_16PlsSyJoluJrdTv"
            + "uAsz0JklKDfPBoto8IgLe65xvCpJqNHoE8WiDKDciP0IPLEBq7NxtT3nsBzQDRN47YxsoIn4vx5tWv23"
            + "7sBDttA7XU2m-GcbI6TMFn-zsRPsoZ1rIGCVkiUMYAPO0GDwGOC979z4mdYltRsNRCV3vTg7t87jQTe-"
            + "2tppJtWJYVi_-s0LwOeeHBVZVVh6nCKzodB_ehSoq-sFRpEB2QF3vPA65qy2-Q",
        "MIIFMjALBglghkgBZQMEAxEDggUhAF7nS7Y_U6OKOBAXly_LHTqcjzjmFYHYGtOuLEIwmvN2a1GcIZa-"
            + "98_5XuN4YNDhlTks4vJRyl40GIVcXElkrTfSdJ1ILYvaSarjyENlU9GUm9PguNgMY0k7y_hIqmKdVPpN"
            + "pzJ7-tbt7zZEihKIOh1AWHlzbbA-m4SDWlFeePY2Qz6yxNPe6rg1Uf8G3QY4-bAMQc0Xx5t0dsJM9Gsq"
            + "LX9CzGRBm45ASbSzXkCJzgbzTsvju2NjHk9eB6orUAzpHiSRQ1QaM-y_isoMzzGd9yqfMLY4yluWH8cL"
            + "izUhKm6lRn8uoyLy7ZZ2cQhorD-c6EknJERxFSIaw_8lQRyhL8NRkciEqaUBgtXidmLfUJitoyZfOnOc"
            + "_UFIRBWWVfM3JKe5HfF-v9kv3OBDxQSq7fMTPzNhHcvmaSFRR1q8ePZ_6YZpYxpRxpeiIvRqJANh5YPj"
            + "FrvXlMdraymIY_6V5Gou70jatVf5PbpoeTtALERnFDIJOpWiuHHU4hWLLAP-tNEHjoZtWu5jccxqoS1I"
            + "qXioXFkywTWHg6J6H6qUROAII-5hu_PFGC5x7cpX7tveipY4M-oATA_HCS_onHY4o80m84VIfXxlraEf"
            + "6asei5G91O3p6nBrTY3D7ShWocncARgj7sWZgJKwuC7ALl5d6cMLQT4FP80PK9GKh-zsch7B6Ss1RU7z"
            + "XcFxOlBdSZUqiKlEGaloyLcCcJNHoFM8ovaplQUuRA2GOfFkMHZ2XkA4xIMyIT5qmDMf5pypEwkz8sW3"
            + "rRdDnW5T8zINjb-ShNPC4UxBLS7GmAY2CLb7dbbKTVtyGJCS0Ktq1NqELzCVQm38PSU1c4xluFXFbvsT"
            + "PRuT60oGhCNaris6ztISISIp6RruzRA587v9NglYkHuYgOt2VOb4DY7YwxBB0tqy3fZEX6pvUmSxM-YQ"
            + "woAh_GUFTB0qbxIKeAsNh4EunxClNpPANOJw4QO6mVn8BpykwFNlj62smcOKJxwoPvdwUrV_h77sWSDb"
            + "9Tr_d_EQp0Cm3Xozv9lcggw0Co334R6g4dPEzBnuIq5XD_P0zHsquTwCNO65fByB-rgs9ZvdUJaaNq_i"
            + "0oF-1Tmuv1uD1F-xeo3Frs3lKMHibk6XJF4IWiBrjCyHeBe0YO9uQlpwd_qpGi3l7KFo0oei2mVhF9NV"
            + "ycCcwWnS_YyQc6dq74A38TsfObBsGqziyYwBBmPAPfqllDrkv3b3yzOJmCxF4w1rYZXJkTCEGtn5es5M"
            + "acxXGWBnamGHeKJ61Z_23Ad_F_ynPw8xHHouGNsR70Kak8a86p-y8FaL-LCzeM3QBMHui_VdUbp4RX44"
            + "8UMh3F_d4znLzGJZkwzrLy-HsGZuOUee9AtoVKS8V0WwesPj7MGBcXTDyIqQLUN8GgA4LJJDSuG3O_bO"
            + "nG_CmcLU2ncuehHWHO_dxWGh-wy34FxNRMo8jns1qdFwXL4qSPa5iMK_NE3xwIm1b3vK847z533pJNzf"
            + "GFAUins9egOvzKu2Kc8YGrkOysqMa-OCzpy9RcEjO0cYKVSx23DZyibNPbHzczAc_0s5B99PCid4V-F4"
            + "H6OXYB6CUQOsVhXP5aFd_0pdQ-L88wkdKBn_Taw5WQf2RxcG7lVYqbyg86iFnXsFPE0UsC__O0VqecTF"
            + "FbrIsCTexjA7L87n4PBnx_29lGS6QUcRiUXsQqPmuT6nKce95v1Kpv5tAUAuvhg9dGDKtNZCvHc_nvLM"
            + "z3Alt-1dlOZbspLG3tw"),
    MLDSA65(
        KeyType.MLDSA65,
        "MIIP_gIBADALBglghkgBZQMEAxIEgg_qMIIP5gQgDVSV9Z9yp-wi9d8zv4-DXjHExplCA0-9aJv5y0lf"
            + "hF0Egg_A2RZJNgtbPouzWV3_T4rM0V2CjO48JvTeyCGBArkn-1ihkip7bCurIhVIRscGdOo2ilSNTQnu"
            + "fcdD62aJk77RjL1N7B6xPjptaspAaqFnzAEHbMiOpIq5s-77iuSKli27sNJRJZlZlTB8kPphVVBmtevY"
            + "1tWQAR0U41mPQBia8bhBFQQTKDAzaBVnMEBwJGczMxEVNBJTMIAId4JoYIRiInNTdWEGVygTUEQCUXgT"
            + "I2RiJIIgEnKAgnE0dDhEYVgANyNwFgZmMyEyRHBYEmhUcVNFFYg1gmFFOIcgNQNxJYcSFgNzIyKFMUAH"
            + "RyVBUWYnVQgzgxURQgcUGHhoI4IIJAFxVHY4eDNgMBQwUIF2NiYwRGUhSHJFhoIHSBYxBnd0EzUjciEY"
            + "AkFEBTExREaEIDEIFxYAgSOIFiJFgUNWARF3dYA0Nwh1ZiRTNhFCiAZ0FTYhQyNoFCRjhXJFeBgjFQF4"
            + "RAcQg4ZIERZgQAEHB2ECI4V0IwQHEgAxRxRhVSJjeCdDAEAWcmVoQ4RHUidwZQWBQRdmYTeAQ3YkYRQD"
            + "VmIRBYQlQ0EUYUIlEDZGcxaDUzNGA1iBRlMDU4ODNWZBdUU3YCgiMGc4FmNoQhh4eIZyZYOIVkFYE3E3"
            + "QmdAMDNnCFIIR4JoMFIWgTF4NzJHE1V3VmcDVzVXcmN1E3KINmcUB2CDMDh3QSIiQAMYOFMHgYhxcmZU"
            + "cCdxQTdChXExckIRFWIGRYgDNoKIU4I0F3gjVlBodAYkSCOHZxMDWEVhGEIoUXKEAQMUCFCFNxclKGIH"
            + "I3UnAyeCdIYBMjAgMoUoRBYlZgMXFnATMhdFiEBDOBU3BEaFEScIQUQnQwhXJ0dGOFdodYhwcyQodkYA"
            + "F0YmMkhgR3JQAEIGJGSEAGBSc3NVFzYXJ0EFMzQ2QQZDJSQwUEGDY2AHOGdlaCBFF1RGc4U3ZDBHVTQl"
            + "iGGGFhQSVmQIdXJWU1FGcnYwJQZkgxVoI0QEZAVIVlBYKBZWcTVRZgB4aGVIAjEDGIWHISRCZiN4Z1WC"
            + "CDYRhWRiYYUFYnBFg2Eid4IoUIJWhBVlMTI3AwNjN3cHdgMzIGVweFQyKFMngGiIEoYoZTZxIlMEYIQ1"
            + "VkZDczA4N3Z2JwIFR2AzcQUAhIJhERRmCCFBVXI2EiNCIwFhI4AlRzUGJYZngVYhUWdwB0WFd3ZGMlFm"
            + "SEOGQASIAFKARGNxB2MRYQhBZjcIh4dleAEidFIlAyZ1RDQlMwY1JgMHgSZSGFNyJYQgAlJUIiJAQ3AG"
            + "RFRDUicFEYhXhYVDYIhAchAIVicmQSRkOCh3JAdyAxUWFXNndUNhZQMSKFKAQyRWMhgiNVIxSGdQIohF"
            + "GIZDASBkgxiEcEYSRIBiViQHY0JiYTI2NjBCJVJiV3FzADdGNSYCMnEzUEJzIWZ2EYY4ZoZ4AERig0Bl"
            + "CFZjZSJiYyc2hEOHKIEyEwNzSDEXaEMxQFEYczgnBYB0RYAXdigwRYgWRiJRcThlMXCACERVEUQ3MihE"
            + "YBUDeGNkY0FiJ1YFVgRGF1IIEoZ2aIYAVVAHZzRlcAQBFRgDCCZBIyUoRXgwQxMTdkGGhUWEdwJDJjBn"
            + "NiEIV4eBBmNEh1M2hnUnJyNwMDc3NUSFIFIAgQNkKFFRABAgQIIFgUMSh1eCNFdQAHUUJQWGEUKFFgVC"
            + "AjCHJiMINAEEYRJUEmhBVIVHCEIlIohRVGGAZlIncUgmBmgVZhdzVBgzCFF0QDREU4IwERCEKCOFEYAk"
            + "BwAzUoV1QQCGAWJggFJFF0EGdiMUZCcUdmKEFUVwFINAYYhwEwOEN3UyhYB3I0KAN3ZygoNThkV3IVBT"
            + "CDcTQYdSZxZkZVc1h3JzV3JzYXeGI2QnUGIkN0gENXEgCEMyEFYIBRWGcScgZzM4ElIUB1NIhQaHV0YC"
            + "YyBGUxdHBhVng1VSN0g3UmFmRGUjR4QXhicjSBAkMQcQNEU4VneDJxaAMyEYMIRiYnMSMVEVVCEUdwVI"
            + "EQJUaIBBACMQZRhhAgKIKCV4CIBUh0IHJnRVAhJWdXIzICJXAGQwSDhAYjHHQB_ZHh5GGkUqM6P02K2R"
            + "t0_d1shPGsudHBapg10i4GpkGz9HNai0g7aXjeaFraIezhv-qvxwqalFDDHTOZzYwjMg-7iinbVYdr6n"
            + "rfLX44YFd6U1Wlu8Qb-dTZmFM1SbN5fMD4h-kSlf8cQ0xsKVPGdssjmSLpqyh4bpt30YFyqwYW-d1Wv8"
            + "mlsbFF8cX-7oOCSAdjiqliDiAdMML9ndZOFQ2SIV9xdRwCAb-bfCjX0eklHvR9kwh7gNhsjv-f0NAJ7O"
            + "UQE1ppFWnTGD0gv7_DH3NbQQ_aQkubQUaePJFEBW6aX0vtB3TnetWgJAnjPrMqGXybHmwKKxhNSww6eb"
            + "wkTCMA2es57Ic0aXi7tyu-h9XqqgHMuoTxKroRUCWDQoa-FqX8WT106r9kD3x_Mx0K8SyReeIcDSm3cx"
            + "8dKJcmWneECD5U-HzU8qVGZBIgNmrsZEY-C0RM9dAvOgFAPteHSqHZoi4Rx8uktsPydyDq9yuG1I71_8"
            + "yTe2WN8_nPBqAOFWUEqhlTwn01p_Z6qIahUovCzjEqhqg0hliui9-8YfmuwTK7AGLYMNwFloz2QlzVEC"
            + "8ALf_8WoSkS8yEsuBTm78j3sEEfhXN6tPWwmLGuLzKdHlFnNvnnmRvQifE8hMzvGx8hsUMEzNkiT-Mj2"
            + "WbZdv0pADhxzjS9uV2LC57sP4a0ct7hzWLvw0V8dGoc_HQep_2Qa46qMb4q1mewQfg15gvU8v4tnIVB_"
            + "Ve5N55RSwqywUKVU3nBRc2oELP6sQjZflLVA2ewhGjdVe00estpyyRYaEXEoNxkZr6CXmwmbVy5IeqO1"
            + "NYt9TPQ87V-97VZqf_g0ygI31wJIy2Plj6c65TGm6c4EvRLLxaYOGW9MCXlUQ9Qzo6m7ifHeSMBp0CvG"
            + "3evT0b3MYRah-9iDJTzyWvrqnk1OCQlxkrWg85GRMW_Wm3RT7z-daM9RXxEnep4qAIztqFoKOl6C386J"
            + "tjBFmWBimbohbiCBsTyUeM7FGP81ibr45irqqw-R8MgwgaKn3PJtI3xXQUcg8jHfvaTKT9N_S-sqM_Kl"
            + "rJkbUGrx_qDo9SzdxmgaVaQtwQgCAQqExgXd5tZktJKD5zAngFsaIkFBKhjNjh0d5nq2Qnt8ekdQmbVa"
            + "SIRqkPRvHE6oSuvp7TCLDzDM46Ha9ChpFvAaE2p7YRGDuPPxwToNbfBEZGv1PCHLOam1YPi4I9A4W3Sx"
            + "ZQbpoNRzEvQDPGduUwhQdgiq0dw8n64Mky0pfwUK0eNr2BcBEW4C1ZMY0KcXQzDJ2hgueVy3-XQfR-S2"
            + "4QC6BBXBSryzYFZQSX2SLANhm5Jrd5fHyJMAvGKKyJUyunm9Vo1WtMyVWG_PcJqqoOVv2WWxrC5HYOIT"
            + "juTZEGqorenM0CZ3tMrLJVMrdcY_MT0MC36qD3Uv30OECqfFYbGKlAoLxgClpoljHy5nxQOqhXH0WmqL"
            + "L8_pNNqZp6_nFWeOBNz335cGEmU90fAMvt2txKBse3-PCkj2UFqJIQsoSMZ0ck7oTqAAI8vDrObjVn6t"
            + "NDmi6WeCSD4eAsLSRA1yOdu60HEyYBY5BL1S27D-ZotG8oIGNMHOSFg6CzATiPU1ubxA6sihOtuCvL9r"
            + "-k8TRmJ1Ct3jegiuRF7OQ01eV1-AvPSLUl_YjDOelVtbaE6UTeqQjv9GVAuRTVn6NuLkk6QAqGF2sVD6"
            + "xY2ZYiJnzUzUSrzLJtHlAh5HFyjkOfMT3Wxi62rbqzziDcphOjbq8tHUDr2DbN8zpGXaNsJDGbMKKxX2"
            + "XrFTlXy-DQuCoNqjkUUnV8Nd1Zqm-RGTQf7a6vYAV0_UWa4uCfWQHmTWiEYk66-MyMpvbu4Yr2jA-dkP"
            + "UHmr9O6KpWF_VjvT0HqrHGkEkx0rwq1zygUoJrsKfpBDhUT9iArRS6iGj11-miKR-4rnPcqSwcldJZfZ"
            + "rM9IR-4hDxo-1-5TbNj4wjeCBhlBSOwtC_XgBCyDSsX_PhBwnZv83d01aKKy20hKr-KQnV2vWqI6TuQX"
            + "Srge_5h3ajmBZDFvEIi96QPKT7c6EtpjHduVwETjT3wezCorCWHdIZUmTzT04hhro1NUc9UCXpHWZ5Vw"
            + "760OtSmvh9uipb-wgIPsWJ3p4BC8_F8dJIwxzlkR3bTDzusHGzMXKaNMko4n81bpIHIs2xlgNFjeHdn2"
            + "gKmXky_NBS8gxw-LaEb8YJz8zf-OJZVODEfgj7d8_1SkIYhReF-ZslE8qDlxencXmCy5xCcccoe3kw6b"
            + "gOZA0I23XjGD0JzfqXVsOkOoFQFyB5GVN3eF4jbPbK5HfaS4UGbFpY-OMyJ0YbanLDUcXvJJg_Tk58Lj"
            + "Fo_Lf3Tc7-qmxenL-9fCWkDtztpkRhlvjSvCMchp9cAO4dLFaXnV0th2TOL_9Qh5TAbe01sZjrvLTypl"
            + "3UD1hB7YXpKnr65n3RgDzTdtA8Kgf8mGxYXfc3JJoZFu1gpulNpNVXJO9xsfCihcKtqcuvU1oF4FIPuj"
            + "6QZiGqmnriECZXjBCbTjG7ncf50T_CMyEFVV8jbss5Y4Taas_enRI3TRw-j2F3pAC59L_YJkSM7V8Zl4"
            + "bYOYeLHiFedr3Q2p4jCt9n-d6kePtiUcodYEgPA-tFKCcMU_GWgJqphZ7vyLw5E81dgFEVi_5j-6bgrf"
            + "gOLjyFJfW2j6yO01sWYzZ832nKAV39czMeMmUOWfsi8fT1nWKIgPWKSdUMuDV2S6-gSuv9FDxb44SO5p"
            + "dRgh4tjDP56RwG51A2gCuILn2jYss5-FMsiZEyp3f66U5oL1Jj9kcrDU7GtqxsJw-2RNcB8CRsdYJaHF"
            + "EUGYcH0-PyVpJwywiCFCWKwzT_A_M5WMhK67LflYSK9ne1XeKNNaX6vWOKPb8Et9-8qSo0rIhrsxB9gb"
            + "jttfzwEYIhjmOJUhlrPS-Jf-00eOP92QaghQ6aqzB_lOijb-Eiqx_t4hbpOmy_bLokmGZgMAvKx9NVIs"
            + "rVLuv-jZhfdNQYKaVmdzSUWc1c_wRvPDe2dAewiZhsFK14o6VjPEUFgp_1U88FI7qdyr_2fiHqiFSWk8"
            + "BO_d9hUQLVeuWmLPaUrSIiO3D-b3PIQT6x0v6-sWOOejtJ0TP7muRvpcF58C22Q7Xmuon6LSmgR5dJ9R"
            + "8gYczfyL4pRhDpgI8LPc18j4apg9qsFTWCAYq8ClEiqIVJD1e4XMcGg5_jG3G8x3Wf57XBHFVlDvQ5AJ"
            + "Qiptqc7F9qUBy2gEwOjOcS-3cf8Hl16-c0J5AVfXlJeNOIcp_QbnQPkqOAnzt44-Zsw27hdfDaT3sUb9"
            + "mJ0VPyZkMlasqzNLXLCcwC_r",
        "MIIHsjALBglghkgBZQMEAxIDggehANkWSTYLWz6Ls1ld_0-KzNFdgozuPCb03sghgQK5J_tYkTyANkiF"
            + "XYeEGfLrMmgdqyITC7SJuSRcDc510OfrN1L0J9eFQOXmk8EPVYe8d4DfEk8E6o6NuKZsYHIBw2fg77vD"
            + "h22YhC01joF0Z1UhyMZq0sP-YuHut6vCSbPs1Lbm03neDqc-W6lGziMkJBENB0dGmc0Zdg6_sYBcs0dz"
            + "lfR7g7BGOgxUvzKnibCjRl5pYxqA9KkfO370992f0Yn0ZHsngVjczQLkaxrcQATWKpf6Yblud2uMKnek"
            + "QfttR0Rbb4-P93IV7xxDNYgwPisZ8e9sBaKLLZTpHsDJvX_HbhySkEOgIrVdBnjKHexVsw9oooFXtv-F"
            + "OtsEATAUzhDQ2_3iY9emiWbnn_kllg__2tQPqHUZe1q9EGkI8bqwYlJqeD5iYkYG5QiH6sCDV3usOWOC"
            + "vdoth_WVvNGF9WP0p1nagMRVdv8kVzkYThL1RN7RTvuEm-zJaB4_4a07Rg-A8egGh3t5MujXK-hk7eL-"
            + "BZ1PVVapQ0cDrAno_AWdpz36tk2nXQGWjQXmjJnG5Q6debT2albV2N_x4vhOIfdENgt1h2wkn8n7Dbc0"
            + "Pun6biBo-BcfS2m9cfo2zriYrijhx5bh5aOMrdd2q4j7mRD2vwdjd_znL1WWYjYDnhaApqvjeHs_kGSB"
            + "3TLZ7DcuNtGr45_afdIlF1AtFU19R79IA4Xr7_x544MsyKQo-hOosB-egJiBcuCLs60fUYNajHqhyxL_"
            + "XYaK_LRdcxvHQf4cQzJ-__bxosp6UOY45d6AWKsYnyGgUsq2S3SYWXPUPS8OSOetRB5-qmjVjsEIFDOs"
            + "pj1hvRs9ebLT8732oHjch1QzDNcfjnSpk2X5qd8Omjhzg6VkiAgUOh18fris_nljMnDkxihUiGv7Ecuv"
            + "yXL9UpA8GxigVvBJEg5eqUc2fU1F9esNpjrMBqivrfMbatvjJgWqzh87x-Wv6qr6-9akTWtx4BwWX6mV"
            + "xyRpEICE8t9yO-jqxKV448R_wuQEBOFn1jxcXXQ36buSxHNsnVn1_dadX88O-osJvm3m_ck5sTl1HV-6"
            + "GB0oPcpS36C_k0btMDLfCDducb_60CgvOlubAAnH_ZPDhSwYbCz6Fny0gV6VzBgFoJXeaPsDP-I-DmSr"
            + "t7e7S6KyZBezKylV6LtkpwGLnFFPDKqBE1ldjTLI2pIpIgQYWGm6yP1or04HMFP35tlE9hZzI-UD_-QH"
            + "72co3PT4cjqPC-51-m5T2iYpLIqFArJk1KdmWsn46L-g_n8_RrmyoPQsnyLjoLGO-6vIBI_Ra3gVyco4"
            + "L_AZI6qkft-lXeofXv4Tg8nl8gXS1aDuSxx76r56hStAFGNCgSSIybVfYrlj4D-jGsJxVDR1PesF_0El"
            + "D5-Lk3Kw53Tmjo_uDxPWp9cTrFX1doGiuGTxmkl1WR2ZCCMxb64VNTGCf2I9w9QbjK_lEo-drzP7hhO8"
            + "I5nC9SlHwv0yKN9asgp-k3sx5IfN-6vU14fDoe6YKZT9HkyIL1sVUhbZ5dm3s0JLp1ZGUgefeywHWqJx"
            + "nnuzioA99_BbudDzo65quuXxAKtGvoYr6El6ESVxgCweqEtCkXSAfhy0Wc3EljcRDKJFUaJm6KmhP4AK"
            + "lqe142pWS-IDXJE9Pmtn4OS0CLWmqs6KgHPmA5znf5YIXfn6UGqMmwoPqsUh3F5twU6UmdqiZFBR1OXD"
            + "KqXzZS9uzZbHqPljN-YiQZOlGXVs_1OMBpJ5W--b1sU5xQu9dXCiQB2ALGe85TlgIEHbxh3XKuVrvszx"
            + "YvKdsmtElUPf8w5nNmxAuNI8kFRA-6kHKG4uZG83bjcWkgrI_E8erRn8f3lew2ZSjFTxtEB-c_WmPqV7"
            + "-fiRXhVMbvQFCeCbHUhh3VcmS-xe9wtabqCY7Ob4j5qklSsi-tRA2myQdM9UP7jdW5nPm8vHK24QJ3vs"
            + "PGgJZli0t7FuNMXujc6avHemXz5AfLlc2uFQvntOsXX6Z-Od75P-xorw5RSbmDHVESBJ2F2cXiF-ymgP"
            + "otuMwKUWnFkdlTER3JJARFDa5ZF8uw5qcRtr1i0LhIrrKM8scWOUJqlP-sSoCRZQamdPSUplu4IRRhQd"
            + "hfIGcZDRb1bZRQZdOMEIyXGARDKS5bx82T1-5Docc7gzvr473JKQ6o666rz3HMdDISKsnsMFSQhpLjZq"
            + "HEuQosLW1aCnEG2H-2RRs9ZGxM-gnSJCDFqHH2MMpP9DUq8ABH5WMHhpDK_D-T1TJKgyRhNXxqDscOYN"
            + "RZgchPFjqX2bPKSQioQeBtgYou7Hqj0-G-zdl35S7lYf1h1B7M2nBUETynMP3l2rl81Oyi3phzVCMyJe"
            + "LxPp3ztVUwZKoXb6-YBzBs9aMKAEX9cxr1tI0VblrRlT_VC2AOcyjpAce-6Xq1U4NV1QTpDYqnOZeMJU"
            + "TFQKExMGGuYOx_jw4JjlJNhSKty_vgOgOUVtQg1MtW0WKHNGh42iM2zfcugYnnOZfPTENv8PUM6Ege_R"
            + "1EMsZhL7Uh9Klo0C6Tduz5oxYPw87Dzyb6hlyH86c-2gZZ5FrXZiRFCZ4Ly9BjVVNSeFeOES"),
    MLDSA87(
        KeyType.MLDSA87,
        "MIITXgIBADALBglghkgBZQMEAxMEghNKMIITRgQgrJtlK18ye72pp9ZwfNzEwUur-IXfyPKOOyyETAvQ"
            + "J84EghMgNRj_ef5EbkI9SyHEez9Fq1J9VoeSpUJtKg_dnFnpmKvWee66qGSHCrKypjlbKgnsO06VrZXn"
            + "wfpEKCKHuEEsgUcgVXile7l6_rrpqxGJExVdTu96UVFtWvTMGIZKPEep6kOYQtE1cKKmFx6W29NrXkUF"
            + "XLJxt_rSb-MnBP5gCFDAKArkGEaJklDQJG5cIlKDkolUpIkkxlDChgwJkESDEGBQKEIjQgUURiIgJ4ok"
            + "E0oKhYRCMhGIBnBCRGbhllESGI2DAkbgpoBboIEjyYWimFAUJoUJJiZKIInbqCHaxAECokwhIE4Qw21g"
            + "GEgRsWTROIbjSDFIOE2UJCLkFiaLsGTYsIxJSAqUxFARCCGkFI4TxwULhQkTJggBlyHQiA0jyAjJIEZI"
            + "SEEjNYEYR2ZIslELwkxcQknSBC7TGAlJNmlaBoZaJEYTEoEaMpAgSEEEKHDZAlIghmCCKA3cwIAZEIlM"
            + "ICghNyKhgohIBCYjIWQTJUbLImnRCCDIxkATyWUQF2EhMlEkRkYaNRFUAjHJwiyBAopkQmZYlmgIoRHR"
            + "Ii7IsmnLwjEamY2JAGVURgVZNEpEGCpjkEWEBo4SJgwhsRBhpiFZNIaaNoVTBI0QMUkKCCThBCpEKJBJ"
            + "QnDixoDZEokYRknggi3DIpDgQgiMiAgEQ0DMSAURNExMIlKBFIlQQmgBlHBSQEgDMoYQNHEhxDETMURL"
            + "RCrIggkaRoCJFlBkJjESBHKKskjhFE4gICqBxnDRAJBiuATAAnFYOAbUqGgBFmrhIGIEOC6csAgKwRAb"
            + "SWgbJ5DIJiRMgi1jKG0hNYTYJkgKwSkCRoGRpoHjxAwIqI2MxkBUokgZookBFTEbgGgZyGkjKQiAAkkL"
            + "FW5kxmGkIgRKkkzgEIgTtI2MFhACxwUBMgLQGAGTxmFCxigatQ0iJAiaJGLctjCkwiQARVEUgwBbGGJE"
            + "lBDAGCDTwikTB4QRsS2biAEhAg6TsmjDiIjJBhEcMikDgwGQhmwMNWLTJpJkyHAjg2GSAgSbqJHYJEII"
            + "s1CMJkRKKG4iIEKcEklTCEUghgTgOFALuQxANDIhgFFCxiEYJg0TMHIjoIkUgQUZKGKICGXSkAiMlCHL"
            + "Ng3IFEIkJjCJFo6hmGwZFxIaQ3GSRCiDwo3QQGEYCC0LCUoiOAnYqEVMREScqECZSELAJioCpEhBNoQM"
            + "KJJLtmHJNi4MBTIIB2YjpTFJsGBcyGTDQAnTBIWTxGUZgQBhQCmBFgRcRo7bEGQLuIgkEXDkIlJYFEIS"
            + "uWBJFjKDJAEcBg3AFGQMsYgbAAQaIopSJIAIOQjEQiLjwEwLuJHUAFGbkmgkIZJEgkAbQopgMooIkWih"
            + "IoIZAg2CkI1UMA2QoGjQiEnZwIFYAipTMhHBsCFDSG1JhIgRkm1ZJhIMiBEIAhIbkowglQGjtihMNiTY"
            + "uIlBEi6iIGoAQZKiqA2UIjDgqEAiJRAQEEUQtmhEyCiZKIUhEUnRgkwII45axm3RgAALlmlYpCHgpChj"
            + "kA0ZQ3GbRG4cAClKgoxARCzTQGqbMoIhCDHQNGmZJkAjFGiKGIiIIg0JBGTKxETcSCpiSEQCFQpLFgoB"
            + "wXEhAyjhsowTwSFbKHKhImYawGBSgm0iFiJMkCACBQbTkG0AGYURxGGZBFKkOCxRNAJgJIYYJ4ATByxL"
            + "wgUhqE0kKRLKkAlaJI0IOCCjEAAkIg5UIBIblgxLMkrbshEApgTERIrBKGUbFQFMoA1ENAQhSYHAqI2Q"
            + "QoUjFjEQRSmBppDMGIDMgo1bRIEjKYZkBIIgBEQcCBEcCY6BFGFIyGFANmDLMGjTEo0hCS5gEEAQFUzA"
            + "tHEKR5DbBI6aRkZiFlBAOAFkoCgbo2QkKClihmlDIGGRtlAJICSkFgoSt0xbwi1YQEXgEnHbEEFCshGJ"
            + "pE0jSEwbFiwQxGhJREacwIhhKITUFGBjgnFctiUiByQkMIYMwHFLBIUCI4rEGELRSBGZNlAKtojBIpIk"
            + "hWkSJ1GQRnKSxCCDEg0BSGFKAkwMuCwjCUIDtGyBGGKkIEncsAwUsGHcgCxTECYRI4SjSJADkm3KuGQU"
            + "JlECmTEkAZADFZJEllGjWfpDtvVwdNEtCkSTklnwmQFDk9AbHn8mro0xcz5UNkLres4A_TQ7945-y3hN"
            + "abmXz3H1xVSNEE8awzQLz9vloV0ICgkYbzrLjKwDBcwXSqJJCKDCtsILbkFZtSkeX18PNurt71iyTaF3"
            + "qA8d32misnezsnCiiBC_Me_oBtg-38QLsCBJRQHsLMrQADcYGVPMiZ59DTo2KLt-ZYF-C3bFhbhBoHL7"
            + "7GsyS9UBLt8Xqh5cZ4cot2CXTGBE-hjCK36HOrMWYJqPzRa4i0wlMNuYTAcKJvjQD26QtFjHx_Xlhhr4"
            + "pOD301N3HngDc4W971iKPi8NZzfBvRlkIJrXdeLHGT3dNjB0U9BZ1KsZR4e51N3klBZ04lSReOwnMVBG"
            + "z8stPY6-DB3ZjbO3nx9kriCfDspURLtcGgO_CLIONj-RADFZuicQ1sJIDDIup0BuzaZbxulURc0noP94"
            + "yYouYTNUPHJ5IRtV4dDBdMBcruNkNbBto0IUUkfDXu1m6XkTtnJHQRKESOFBeBL2Gmbq0eICSN4C6kqC"
            + "vn-OjQKpcvEkAnCq7XlcpGl-JxbMJub5pFhvTCUGAL_G8buGwAnKGgXzHtuZISYU20qU0vgBkEoukx_T"
            + "pYxQkK404z4pMi-7tipVeMI30Inzrbd-6IIx9_TnmJ58gLuHPpNMpAfTCamDW0c9j0uvpgt0nkRf2VNw"
            + "YEbWE2hGN_N1ou6ETx9EDs3C-c314c7D1cRzDKJzp3t7vDIZV1yceVazvZfFC7Ll2Y3GJahrcnJJOrLj"
            + "zEKWqV6NxBomYm-YpQN90z2q4s8f_uUUigKG6DD7Z-r4SD9A8zBlCB7-ALoUUnT4rNwXog51B4KKI1hZ"
            + "vyAJfaaQjzLBsPjAsUypnW_MQ8mOsHiDaFUA8swxg_nZKb63CWwpT6LeC6B5x2wcZcNdpkl6T04To_So"
            + "obi8nsto9-TbJnG5-MwuA7XkF7LgoTABunqBUo6ECa3_25NPfJjKDCDXKmn6pCpt_pMOnaeSSaz--sl0"
            + "7LgNeT0nH6UuqTI1AjBbfNKWBSvmWY_vI3xWtf_bD-eL2lQB4npsJOMsv5jk_7Y6Ok1y65-UyxncHV4L"
            + "f82N61bStji_5LXcVovgpTR-zirCWyBkNvKrEGE8YzBgf-0wRTtPa6MCqOQoT_cGdHaFfHpuG8KRDMRt"
            + "gINXTO_gZAQJtKybDtTxgrWdHn06X1rsKGVJk5H9P4Wh_2s4p7URqPhZAd-xhrPP1HUbRcXC7QAzl5LW"
            + "eAG9b7VIHpmMjVFT6BPQaZSi4BVrMQwSQ0treit4HhTeIDjOjwrn6Iq-EukwPjNPC4-IiCVZhPND8otH"
            + "QsAoNyGqWd2xXZOI7QIJNtp7vbg0xsGDgU0FLaSacTpan5yNiRXZJoqqXCZrhfrRSnSFGHK7exNw5Br5"
            + "EOBjdExJueTSbQTL7QgIiWIIqrzq6tIf2BNTlzux2_ILZ_VDoXsGjR3qhEvSsjoTZE5Z6DBnn0GTFG7A"
            + "Xu_xH1NZRcuuPDdZCLINcCiiQrULRwOQjDbxcNBM02ZMb1g1_GqLSl9-wpbOwjkA7u5UQpF8tvjwp-cy"
            + "N0Tz6kPi4mAVvkFbdrcLFXdeBrAPEaXsqQjOMekZ41I8HzgGYbsyqw7UC3PUstJbNdjB0dM51EAFJGAS"
            + "FDjbwczcG3tp57yPijRADIArG4xDYHTBhx4ukX2MGWmjvtqJDBPuMq-X4zaBemtvhVJcQ8OZDwAY34fP"
            + "6lC1D1V4Ma5z2m8oQ5gfo3RrN5NplrFs68aBDU8VVtqu9GXbkhrXAWveswxN04BMmiYtf8Kq8CRLV-JG"
            + "nQ20zcsAW00M031uvLcRmxXjummKd66WR45sIaJUzopt3RxG0M_31LWMQ4wPrtC1zuw2AItjsy9Edtex"
            + "sZ5bg1E0uu4VPy_7JnYk-8zbWeJwaXF5b0IvFuHQO5gV9Fk2Kd-GdgJ0ekA8NIVqSZY4fm6pHGEKZM9P"
            + "-3ZBrX0FXpix5hLXc_lv6ELdc8ej6n7dLD3ehgELan5AFZ_tmk4qiiWlEb_Udd1lKzsw9HA1TqykJpkH"
            + "uEvaXjQ6Cx6G_3C-TR25mgCRzr6zIFU2UczmHpnV5Izm3DDKf9YdndrVTRHrXlZq_iwEPNvs8xRrOp0T"
            + "yao9ZcuaibVlDbMlVidlt8VaTl3Qr6EvHLp07HraP5v5u2vfntTw0H07CKLv2hwMIKWlS-EqdeRu67tv"
            + "-X-RTO7lejJqvyS65S3JdtZ0IDnJEUlbWGK5zyP1SYvzNejcklM59DxK_IriarXNQc9xVcFsO-zt98-e"
            + "5EZpTMEZMWbj-dwg1IYxeyGNlLcWepLZf11RWEg3QnLHXiGG1SAXC7V1WQjfxoVmUkktBJE7bG-f3MHK"
            + "MCmg0G11Zu8MEu1HHMa99V20aNKGOBk0wNqCyRapav5zbSd5oif-ESnz7GRPRydNJGxG5_Z9btNni8wz"
            + "_yNscchKbxKZjnBgX1rtNOWGCb9wpbSnb6DpqLeCV5kAELgYHqL9HJQW60x7pbtO2D2iDLiUTIo0BLRN"
            + "oS5NcmtMduBMgEPlBlqJfk-7Nz3EdzeT5D-XJSznXSXMpgMrX2ADNG2pwlAjlqSwjWVX5UF33YXcGM9z"
            + "Y5ObEqnqZu_AfYznm3uCVtSdnnfGWj4Ym-lDlWlFvobK0AHLFYk-7PCUOPCtd5vhGVQZacxS4GlogMG3"
            + "iRFVBJWyTvFELbm0LABZ4OnTj_xCPdpj0eMF3c74phJMxMYEZz2kjQ6A9r9FdzMlcY3pS1Dgg3AjJsQe"
            + "BuCypwJprOOHD8OrjlaD5cVGttCZPx0sM2cS2Cr1W-49HeA9iFd2HvT4boPcsA0gKZ4_QGiS4fjUVPgy"
            + "xNGVNSKFeUh3mIp5UlE1vd40uY68bd9FxvCennE38AKuO-Gb3wf2qIiVnTYwwm1AuREjrGUbm8eCgW2a"
            + "rbNoSAUpY2ovuLFQbGwASHVVDMbqI99rGGAWfeBK2ay5vG819LFm5Ohl48FQUEODJytus5ZbZFlg3IEv"
            + "aZ2Wd5joaiMOhsfdtgJfCbr91RgisZeIiwXLnYh1LHQ_UfTiwB23mVaHg4q_wcT_VPeXgNwOpoBAZfAR"
            + "vG2RZNLoFrzp3jlei1sk-OnYP_Ut_cbIXxI2-xgmVEeB3wiszjB9uWQFo9Bj63sdOLoSRE70VP5uPp4D"
            + "lpZ96sjfpvDxP5u5NVOcygWZBTCHF2hjplnWR0JUUfa459BTGJfPKE4srWWym4fwYtR_42dNTqXmpHJH"
            + "SogfzbAYe2xm65zifm4Gwdw-9FAsdpUbPEXnwtVgxPwsJ-yXsxg46ZR71FvjRqK0dG47n9CSLAe7D4CE"
            + "JFORSPvnyGm3sUMHfpjGHkaQfAccRYwIVJa5f5JE2q1fvbEGpfcDv9mjfCuX3Lva7kHvtQ3iqX8Lmok6"
            + "i2hNreercMurA-oQ2wAxkqakDXjsYJwC444FIp7uAAPAFpo6CG2nfdCGt9OCIqWoTTzNTTadBvJ87k3x"
            + "xQNpfZSb3I9X2lOKWCC83vggWXhGotcrJT21meFRTEOeB6J-1fOCYApFnila2xs4X8R4n1TjbtnSBiWr"
            + "f_qool2CkiUF50oj-4ZrWslZaovSn_dRy9-tsSXw1tjTWuaWpmUTbhlG8APG0wccNfiLizc6ZmVo5sBC"
            + "1hAawibVhaPDO6wZQwKHuoDyqaqMaUNnP0L5KIHanOu8aTO9_gzPKTLo7E-slOuemuFay9aLwQRmWBgT"
            + "ombYs9yxaG2S15yemVdpGROoe5yCyLeloVDdTz2eTO4lxTkS2jWewSnw0cuRC4t7keLnWseguL9E3Vsa"
            + "jV69tpjaQfGt5Ad6qyaa_efL1ZBeQOS5KjhcsPdVg1nN_jxEmlicrri_x1RSbYNfFUqhuhMzClgf8C9U"
            + "h9k_hDXDcsTemrmaG2MjJd17L9f-vjHzzdeW8oeoeIsf3OeIf1UtBIFpP3QqUaOF107oAZiYlFBc_chB"
            + "SqfzDoQBNa5VMJasmwTtu6-Kb-75jvG0kvIJiTM_117XJGuj_ymGPgnQ9emtqeul1X1BS9ow4OSyXPvH"
            + "zDwjp3iT_m5ZHrYAp7MoFD8_UTcIJVfAai2W3hPyXVmqyGYQE9w0pBRKAVWf4R2CoXj08Cw17wed9rRy"
            + "xy_y3hkj7Zx808OPySPQY7e5d7-ActPJ12leUFeFVvsvPoQlGY5aaJUmbqhPyv4ON8xa23nm-b01a_mk"
            + "rPCUOblp0xK0l3PqnmN6kfWh0KKklZsCPQbnAhoyhOCOPgP1RRbBB2eQCX0qPbM2C3eB07BH1quG5DNL"
            + "oMbtzZXrOGIwBuRJkOJ9CVreXZQ1sVRyK5t-ZqGsztBKVJhLKGhrx_N8TntVjh3WTFOJjaiNU5zdjx5V"
            + "4-_NeZOOr44xKRXDwgsDprDhPwkkHoNPDjQqFZh6Q1l_iwAnxzOIlr5R",
        "MIIKMjALBglghkgBZQMEAxMDggohADUY_3n-RG5CPUshxHs_RatSfVaHkqVCbSoP3ZxZ6Zirct5HMht7"
            + "zltXml-4qvoWq7KJlGSPgEU4yXIY2fS621OG-9csmAJb2ha1Yu9VHjIl4o0QCa5xJo8AWsbqlEywxn9s"
            + "q319YRTtO0oUVBWFDG1v15TCzX6sdSLehDKY7fM2QnydXs1_KAs7V_TOj5OFcGJHTK1hKa9rxn90rqwI"
            + "iqqbZORnzZkvQI034Xq2qElRXYOtlSUO2-qOZheRz_Ml1mkVcatkYzSP8tgqTGwdzbT64zRoE6qxVMtf"
            + "TCGRtuvRvxI0VElk3BViCHPlg-tHd1V34T1mm6JYKyqSpxw3gtCyMS0_DuVMu4QlEcQe1KYLTDC_fDPY"
            + "p16QRkTL-UqprVuHq8CHcpi3xp0APsKKz1LeN_cjhf09Ow27CVgQLTUUjlnAMao_x7wf3Y1zpJbNXwvC"
            + "JUkliVoD864P6gMY1bCfNA_-39rf9vYGSL46GDB5I0UDoVK0zZXL8IIMrDLWCMf2wGSYXbMnfx0qH1Iu"
            + "ZTmieYRAWKEwLyO5JMLnMUw_QBFZNIhH3Lsn-Ik9QicyG_aAyBn7buk2zxoBWGH3IT2EhGKrLQLY-pmB"
            + "sKxC__l-UxCSGVV4FSnrG16ZPB77hYTkBi1neppHSa0SmM0bkj_uHMPXez7st0vqv83wz6wvA9GYQEUJ"
            + "biLA7dZ0mk6llzxmhy1oGTgJNvMOOU8MImo5kEHdLoJJEAC1cCF7B4UKez74r8je8JAOuGfqcZhF6ZU_"
            + "YPc-A2bxFlbKUSOA93no5qepzTwQG5Zg1gt6EBG5jNQA1CKh3-J5R_srwI2gew-wd4-JFuYx2UkPca__"
            + "qaP3TrGhnRW1swB2KLzqwhR6qa2ALAkPx0vHEehoSHFHG0QK1TAY7usNTLmROSzQwk1s42M7Vme9hdX4"
            + "wgl5Ymalm1tUEZTYHG1xFm_3YAnmG8DRmwHqrjRsX3hmxCLgnEUucls_Wcx0qO8vKoMGceDckfKUCV_8"
            + "92wNX10xIbZlCRRb30XVn5eN5REmFdDpFU001lsg1UVde1wTetNQfB-pmaH431k49gfbBMxo_FxIYjfB"
            + "6-rk0tgdH7K1cGpi8W3lPJMuW0ee8D1J5prLZ-dWOEnykFfDo0FD-P2tJnsYYAipWOl32j_NZihZSwzv"
            + "UigZ9nA9rRxhNHpgtsEIcLuPxFU47JIhKEqCzTB7t9PT5i-KOixDhof1QXDay3VvUfr-Ftr7wc3w-XAb"
            + "mLkeL4znD_C7QFZLu061DVx2r13nDy3cQXlkcDMLM7Rbovdt6KVqxY5-LC9GFeRQqd4E15qJ8fK4xAsJ"
            + "8vuNvSiCoio2VRfxg6Zeo6vwKw6qSKN3BHgzQjybXHrnFpKTVek1Inp3EeSye2-ywFbe_4HP3Plb9XIu"
            + "B4d_jmNGLbDl-Pi5S5y_YxXKBQ-8CpOoYRdfMh4upFJ9NRoa3ZW4mq1Q-_So_IPz9z_CxsmyJvpab1zH"
            + "BrjjPtD7NTOx4Wp3-65Iw0vLsBC7iZlgYdy1yA0IT-hs_m5RsrF0mpaw9_LYSPUEAZW1wHNUGtI1cpc2"
            + "2vLkhB7mxDUqnNzOKXvuGic2JEQyi-w1GWYv5bZFeTiA9cqi3jb2--4zjct1WnIv49YynDI-2IftiOp3"
            + "tpdEYwyjK1xWKSirW88ce0fAT8Mv08uOftHHVfmLJZq1Ew52szgw7VkrV00slB4lVo6he95YoqOSSgtC"
            + "MwQmK9ANa5tCPqxqE8ssGaDKz7nuyNZucy5KZRrJcuV3oHUqcdb-yjYUB5_kV7Nq4uEOooG5vebXxBdO"
            + "3iRwXSNrNOVQPl707-BDonAqbucAT07upAD_iWhFW2Smmh2jucTfWDQgkXzFwTEE4AOLlCAGCcgCrUjL"
            + "Ekz8Hca8YnCj5w_5x4JDeQwMSHNx9f48kkcPovZ9JjmZHPAg4QE1ND5dk63a7Kvd9FURcAXsO8VwzGk7"
            + "7Sa9cdicgpVqaesHHzQczpEF7wnB1dB8qiOt0nu6BZ1dZhiB6q9QIyEIyAuyloRFd3NF-gEOj8IZfnMJ"
            + "1xwVa_rXNwo1XYUEcoJrjLXhLb7riYTSUSYaQJ6eG7rfE4VmLzfLkj6B2mQAG1_Xgm3OPC6FwQJpfUGc"
            + "pb3ZrkJ73m95PQuxpU8_mSne190C9lFZDodFiY9v4SWlDHz08APAl1EtfoC4dizQweEDRP1l8zqcDRe6"
            + "QBWNCTdjAYlooyWoY8AVCrSSfkQfcCU-rMc6pJioiSMP3RDw1lHseR_kzxMXilTuDftGEj58h-2AsB5k"
            + "_0OL6XLVm3ZOZTPznEjVl0M56rSkU-SPY_vAkNU_Gh-zk90lYX7JbFDP_1NnttyTblMIA4GALs3PXWz7"
            + "PEv9MQoS5ctol40TcjICwKkYOiiv7dfKRsl5moiKGwJH4aHb-Hp2BRpI_kES8HMbK3I5IeDXFRrOtKSK"
            + "SMIOQeEg8vuTwJU2UVZ3rpFzU78SNHPxc2MoLImx5alNzIC118FkruHbyamaR0dW-Fj9JoUYWUoQrqQU"
            + "NpBWKyzccQ96HSVZV9HtHm1DxN5TdcxuRhJcKy78MNudrs06cPPgN-GRSudO-2nbA9ms56MRsnB2aTGD"
            + "iXoduo7DuQg4ZXVHndfS4xhfycIVy4AwkuMEZUxISr2SSh9xaQhWCRvKi6wkVUqKsYt7Wm0C5Epa_QDu"
            + "dgbtqAzfzsLdMrhnDwPxo1ugZzKAHfpe5zrbt0w_3MZffSRMfceIy4j6KqOjbe3rNj-n3d64_3VtWc72"
            + "uUFBpeOI3tCLkK1qn1A6y7tXwXdb7xzvQsc7LRpyHV7fWI88XwQF2YU93wz9UTgR8DC-Ju6M5BWjhwrP"
            + "TIxepgflFA-nn9pYExfxDLt2ZBFlxAf-ONFpBVnRvPQDMNSFWtLMnPTdmw7cT2OqN5TCYS6Uqq9ML2Da"
            + "Doiw8xihyDikctecMYMuH5X4Ke5YbrJ9jGD1J6fYtTzT9v2789p_0gOLOFvSa-Y_QPibGjCTczubzaXG"
            + "uLhe2ChxNqXvjgNQuD5C8XwD0g_Sw6Z6cVBfJqXaRB-jqvvncnZ25yaLfDMjwLcgifgVN47p46HH-NLZ"
            + "_czy258f31XNfcIi0gK2FZqkmIyw4hLvKtZP5CKjS0PQFM5gKqu54v_R-Zcny13x8q21D_ebmS_1Pu5N"
            + "NvCRO27SSVW11sIs2TnQc5TaNUoNACJhcdOubeIB-dNk0RnfE3oKPgZxYUluTe30xc9GSiIcb-DT-ks9"
            + "Mg41lhobuA335Wou_027QRWiinRq0gTrcHFfsigWC8IxIu65pYISaTfOb6ffvySEMZDIAbsXVh6_l6In"
            + "NlhTdtQMaXFt8z7Rd5ydA8QhH7AbLyMd3fVxcvNwZHjbr-9iIq1KTBMuc8FAA60fEYujNp6XWa_aujv5"
            + "Tk384X5TFXcPzZHc3zcwOBW7D_cIweMQRSARiKFOHheMFg");

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
        String algorithm;
        if (keyType == KeyType.ED25519 || keyType == KeyType.X25519) {
          algorithm = keyType.name();
        } else if (keyType.params.algorithm == KeyType.Algorithm.MLDSA) {
          algorithm = "ML-DSA";
        } else {
          algorithm = keyType.params.algorithm.name();
        }
        KeyFactory kf = KeyFactory.getInstance(algorithm);
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
      case MLDSA44:
        return generateMlDsaKey(MLDSAParameterSpec.ml_dsa_44);
      case MLDSA65:
        return generateMlDsaKey(MLDSAParameterSpec.ml_dsa_65);
      case MLDSA87:
        return generateMlDsaKey(MLDSAParameterSpec.ml_dsa_87);
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

  private static KeyPair generateMlDsaKey(MLDSAParameterSpec params) {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA");
      kpg.initialize(params, secureRandom);
      return kpg.generateKeyPair();
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
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
      case MLDSA:
        algorithm = "ML-DSA";
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

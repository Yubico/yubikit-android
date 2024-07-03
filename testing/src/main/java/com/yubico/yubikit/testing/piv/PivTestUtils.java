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

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

@SuppressWarnings("SpellCheckingInspection")
public class PivTestUtils {

    private static final SecureRandom secureRandom = new SecureRandom();

    private static final Logger logger = LoggerFactory.getLogger(PivTestUtils.class);

    private enum StaticKey {
        RSA1024(
                KeyType.RSA1024, "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALWeZ0E5O2l_iH" +
                "fck9mokf1iWH2eZDWQoJoQKUOAeVoKUecNp250J5tL3EHONqWoF6VLO-B-6jTET4Iz97BeUj7gOJHmE" +
                "w-nqFfguTVmNeeiZ711TNYNpF7kwW7yWghWG-Q7iQEoMXfY3x4BL33H2gKRWtMHK66GJViL1l9s3qDX" +
                "AgMBAAECgYBO753pFzrfS3LAxbns6_snqcrULjdXoJhs3YFRuVEE9V9LkP-oXguoz3vXjgzqSvib-ur" +
                "3U7HvZTM5X-TTXutXdQ5CyORLLtXEZcyCKQI9ihH5fSNJRWRbJ3xe-xi5NANRkRDkro7tm4a5ZD4PYv" +
                "O4r29yVB5PXlMkOTLoxNSwwQJBAN5lW93Agi9Ge5B2-B2EnKSlUvj0-jJBkHYAFTiHyTZVEj6baeHBv" +
                "JklhVczpWvTXb6Nr8cjAKVshFbdQoBwHmkCQQDRD7djZGIWH1Lz0rkL01nDj4z4QYMgUs3AQhnrXPBj" +
                "EgNzphtJ2u7QrCSOBQQHlmAPBDJ_MTxFJMzDIJGDA10_AkATJjEZz_ilr3D2SHgmuoNuXdneG-HrL-A" +
                "LeQhavL5jkkGm6GTejnr5yNRJZOYKecGppbOL9wSYOdbPT-_o9T55AkATXCY6cRBYRhxTcf8q5i6Y2p" +
                "FOaBqxgpmFJVnrHtcwBXoGWqqKQ1j8QAS-lh5SaY2JtnTKrI-NQ6Qmqbxv6n7XAkBkhLO7pplInVh2W" +
                "jqXOV4ZAoOAAJlfpG5-z6mWzCZ9-286OJQLr6OVVQMcYExUO9yVocZQX-4XqEIF0qAB7m31", "MIGf" +
                "MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1nmdBOTtpf4h33JPZqJH9Ylh9nmQ1kKCaEClDgHlaClH" +
                "nDadudCebS9xBzjalqBelSzvgfuo0xE-CM_ewXlI-4DiR5hMPp6hX4Lk1ZjXnome9dUzWDaRe5MFu8l" +
                "oIVhvkO4kBKDF32N8eAS99x9oCkVrTByuuhiVYi9ZfbN6g1wIDAQAB"
        ),
        RSA2048(
                KeyType.RSA2048, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0G266KNssen" +
                "UQwsqN3-f3ysmiHgp4345wsaiDcxXryXX3pXr3vYdiJFQ6HiiMbfdpm4FeulLYCOdBghKHIh_MnxTuw" +
                "q6mPrxzLFxqGfHinvORc4Y-mZSiicN_Ajo-uQdgH5LrhlHJ0g7ae26RWW3Z4pOel_SeXWJgKm4prhKz" +
                "i6Or3NZ1l4Wpg4C_lrLD9_bhL6XdUmr_kXc2UoldUz1ZyTNmDqr0oyix52jX-Tpxp7WsPUmXUoapxVp" +
                "ugOQKlkCGFltb5jnaK8VYrlBfN0a7N0o-HCSIThjBLbr65qKXOmUYgS-q5OmidyeCz_1AJ5OLwSf63M" +
                "71NXMtZoJjLdMBAgMBAAECggEAT6Z-HnfpDc-OK_5pQ7sMxCn7Z-WvLet3--ClrJRd0mvC7uVQ73TzB" +
                "XUZhqZFumz7aMnrua_e6UlutCrI9NgjhgOoZzrTsBO4lZq9t_KHZXh0MRQM_2w-Lm-MdIPQrGJ5n4n3" +
                "GI_LZdyu0vKZYFBTY3NvY0jCVrLnya2aEHa6MIpHsDyJa0EpjZRMHscPAP4C9h0EE_kXdFuu8Q4I-RU" +
                "hnWAEAox9wGq05cbWAnzz6f5WWWHUL2CfPvSLHx7jjCXOmXf035pj91IfHghVoQyU0UW29xKSqfJv7n" +
                "JwqV67C0cbkd2MeNARiFi7z4kp6ziLU6gPeLQq3iyWy35hTYPl3QKBgQDdlznGc4YkeomH3W22nHol3" +
                "BUL96gOrBSZnziNM19hvKQLkRhyIlikQaS7RWlzKbKtDTFhPDixWhKEHDWZ1DRs9th8LLZHXMP-oUyJ" +
                "PkFCX28syP7D4cpXNMbRk5yJXcuF72sYMs4dldjUQVa29DaEDkaVFOEAdIVOPNmvmE7MDwKBgQDQEyI" +
                "mwRkHzpp-IAFqhy06DJpmlnOlkD0AhrDAT-EpXTwJssZK8DHcwMhEQbBt-3jXjIXLdko0bR9UUKIpvi" +
                "yF3TZg7IGlMCT4XSs_UlWUct2n9QRrIV5ivRN5-tZZr4-mxbm5d7aa73oQuZl70d5mn6P4y5OsEc5sX" +
                "FNwUSCf7wKBgDo5NhES4bhMCj8My3sj-mRgQ5d1Z08ToAYNdAqF6RYBPwlbApVauPfP17ztLBv6ZNxb" +
                "jxIBhNP02tCjqOHWhD_tTEy0YuC1WzpYn4egN_18nfWiim5lsYjgcS04H_VoE8YJdpZRIx9a9DIxSNu" +
                "hp4FjTuB1L_mypCQ-kOQ2nN25AoGBAJlw0qlzkorQT9ucrI6rWq3JJ39piaTZRjMCIIvhHDENwT2BqX" +
                "sPwCWDwOuc6Ydhf86soOnWtIgOxKC_yaYwyNJ6vCQjpMN1Sn4g7siGZffP8Sdvpy99bwYvWpKEaNfAg" +
                "JXCj-B2qKF-4iw9QjMuI-zX4uqQ7bhhdTExsJJOMVnfAoGABSbxwvLPglJ6cpoqyGL5Ihg1LS4qog29" +
                "HVmnX4o_HLXtTCO169yQP5lBWIGRO_yUcgouglJpeikcJSPJROWPLs4b2aPv5hhSx47MGZbVAIhSbls" +
                "5zOZXDZm4wdfQE5J-4kAVlYF73ZCrH24ZbqqyMF_0wDt_NExsv6FMUwSKfyY=", "MIIBIjANBgkqhk" +
                "iG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtBtuuijbLHp1EMLKjd_n98rJoh4KeN-OcLGog3MV68l196V69" +
                "72HYiRUOh4ojG33aZuBXrpS2AjnQYIShyIfzJ8U7sKupj68cyxcahnx4p7zkXOGPpmUoonDfwI6PrkH" +
                "YB-S64ZRydIO2ntukVlt2eKTnpf0nl1iYCpuKa4Ss4ujq9zWdZeFqYOAv5ayw_f24S-l3VJq_5F3NlK" +
                "JXVM9WckzZg6q9KMosedo1_k6cae1rD1Jl1KGqcVaboDkCpZAhhZbW-Y52ivFWK5QXzdGuzdKPhwkiE" +
                "4YwS26-uailzplGIEvquTponcngs_9QCeTi8En-tzO9TVzLWaCYy3TAQIDAQAB"
        ),
        RSA3072(
                KeyType.RSA3072, "MIIG_QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQCe4Vci7OxOOx" +
                "ek5ZJ_A7uklWpkiRvwAqguotUwDwXybJqvz2sf0TMgYbSweBLrnt253-w_cJUkXeRS6JgYJNPM5R7zt" +
                "aWL8Jsl3ETZVwpWJYZ9cRXmI71kB3ys0ROQwP8Srqw0vT3R6d8DOJ6SbQveScG4Bu5QG_OpFvfwS9qx" +
                "v7OJGVbTV1w5lPBzQGZ4AFz0annGgz2FVZ6q61LgabJfjMygxWPNQjbY8HdrsGz3T8RMjb3rRhNKxlZ" +
                "mVZob3qGpHxcDqvWMSz9aPgSzFTBWyIKv16_rzMJWcISfm-Ye_jpRAFV1quKHau7XPJJoMDdOF0FPyJ" +
                "SLckt97aRjGBG88OwdW-Aj8xMA25_Zrx4Ja_SmHTBX4RGQJgM4qwhZV-XeHfNX5uML0tZgMIi6PzzbX" +
                "aF6VIpDF7DsQEkMNheSXcWoD7Mf_gHS_coj0DP8VEuaEd_u-L4EvJHrbfVZ1cwhlIlhE7MrfkqKWZAr" +
                "ypLarrZ7V7shU5pZZe0GEQkc6i0CAwEAAQKCAYALPBd_jH3cPVD7c9FjYmXxKjCjCc_8LY_rdk-5bYK" +
                "H5TaeAn6Kei5Rlp8ikGcUGsCGjYdE6CbfsrT7yN9Ca84_UZ9Z7-kUJ3AtIfGLZdyBAXfMZIP-KV5R1b" +
                "ay-LjXtlIDJe9e7lfSAWXn8ifCZmwdrJ0CcJkG-KcG-K0RJKgDBDGDmxNY7_dBSh8jozTrvOjVzrasO" +
                "ykNRePppajPXiIDIC9zGeooAEvlFMH5DzlxVoZkvGwm2CZylepTo695U4mB6FbzGxHDCXjYVAsQDULx" +
                "-j670TjnWkmuqXNGEN_SGgAdsEA51gJv8ar1at3nJf2LleSYNAL6sHOski9uEYXJ3CacWvnZRzT_YNT" +
                "7WKujhmIS3EwOZgbrYI3QreOls9Vy-Xo53oCwiAii5zvxDMkZmG6oOgblRsV4slXtNEaL1mN2vM2_a4" +
                "_Kg_yRmzFMY9znYp46qDj5QbmQ5MhEKgC-_DOrX0ih09eNlrgK6nb9VxlI046zthxY3beq47Z59mkCg" +
                "cEAy0KHoX4vA-llBohsGiB_mCa6vvpdYk-uKqUcnEBG9u7UFEXKFn3n7ern2v6D1Om69u4S4_PIw2uS" +
                "MBZ89jhNpo2WbX5GI_zQ-DCct9HJEN7vHM9W9AVuWLdn6_HM8PzTvrke1ZKGXorug-IWww6uaaBj-9r" +
                "HJTTq_Bg0oUk1jv2jianp2Ct5ScFm4--kIjmb1AuLebywCvMSxZ5VtYHfb4VRgCM-nAIOdv9s27FNky" +
                "VKHCgjK0dkLCMB0DgoTjGlAoHBAMga6ETh49iQtCAJpq28cQnqLSOCUI7dLqJcnEitUL5PtyCFkrpS7" +
                "ZfLr15cHi4Ud9ycxtbaxAlaNtLo31l8tpLgbeVck0Ke67OUMRGrq9ONVXTYMNNX3tq2M7XO2slKa82O" +
                "_tUDMjVlVv6v7R-LXTeqXItgxdISg-ZAYQHG550n6Ldterc2WxGOFZNjD1fkgbdwnu9f9DT-jS-m_C_" +
                "oGXD5iqAaV2ovcVFb19iubRrltcqDi1nyhXnyKyjYNXff6QKBwQCBdsPLAgNSO4PEkHpCffanY-vInt" +
                "GCP_xQX1CE2ZAZ0m805mrcvp9OdDPv0fMIV0Nl6qgPl4SFrGu1w20eqygScNaisS5d17cGjngTwUSPQ" +
                "WAN-qaI0TjCuzcvGpmN2YvJTEIuiKCbcWSQjh4vaZd_4dAtZ-E2eqk9nvFO1cGObVGP6rDupmofp1cw" +
                "0b-6qPTvL9dL1_pNTxvi0YIIFUvKzaDmvAwx9EFgXDrrB9jAY5z7qDkWZOeSEU4jYNGTVJ0CgcBlfTg" +
                "mj4b29NVWlm6CGVwfkjTYmKRxAP9A-8WMGtMj4txXU0fK1nqIjZbhPclUx67PJni2yfe5YpcBu3hkM5" +
                "uJvOgf9yb9GAslZljIxI_-WOVpwKhq2FtABD8Py90tUGCCvi7DLL7PVBmeTO3wHMfnjrEnQ6qxVBCvv" +
                "CE3PIGGNJKUTaN6vsfLjIum2AwVIOElf6oscDc0lZJYA9JOHeKhaP8FGrcRNQS9Jd7AmB7gEHd2Qedw" +
                "dE98PPXk3lun89kCgcATb1Hcac_ASVlLfyNvhEWYS7yHfALvGlCSTv-zdsIhnZ0oeN8ILSmzM0QaRB6" +
                "matSnt-ocYJmJYuVwuzHFwZ-eitjnEmVMuMAMykUV40flaATPqERZvJmVmZbbCBv5qdb48zFkXQtR4q" +
                "USvg6GjGUL7CAlBEjqW479l3KtiUuUF7WlIfU-iHhbA7HfkSbN8gtTorX5_t3OwZeFf-OGki5Iaf92u" +
                "oq716yEBvD45dbPnkJG5sQTWDIHIKmRcwQ9ibw=", "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIB" +
                "igKCAYEAnuFXIuzsTjsXpOWSfwO7pJVqZIkb8AKoLqLVMA8F8myar89rH9EzIGG0sHgS657dud_sP3C" +
                "VJF3kUuiYGCTTzOUe87Wli_CbJdxE2VcKViWGfXEV5iO9ZAd8rNETkMD_Eq6sNL090enfAziekm0L3k" +
                "nBuAbuUBvzqRb38Evasb-ziRlW01dcOZTwc0BmeABc9Gp5xoM9hVWequtS4GmyX4zMoMVjzUI22PB3a" +
                "7Bs90_ETI2960YTSsZWZlWaG96hqR8XA6r1jEs_Wj4EsxUwVsiCr9ev68zCVnCEn5vmHv46UQBVdari" +
                "h2ru1zySaDA3ThdBT8iUi3JLfe2kYxgRvPDsHVvgI_MTANuf2a8eCWv0ph0wV-ERkCYDOKsIWVfl3h3" +
                "zV-bjC9LWYDCIuj88212helSKQxew7EBJDDYXkl3FqA-zH_4B0v3KI9Az_FRLmhHf7vi-BLyR6231Wd" +
                "XMIZSJYROzK35KilmQK8qS2q62e1e7IVOaWWXtBhEJHOotAgMBAAE="
        ),
        RSA4096(
                KeyType.RSA4096, "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDLqdGZtBymZ0yz" +
                "MPApteDlEc0hejP3Vee7i9L8V23HytZyQak6RrlsDPSLgpkn3p9IUZ6fpMN6ND5T" +
                "PCvYiGu69Um1MUHlE9n3iZEPLHzu1EhgUHpZMlqAwJYPq1B_CA1yuiyjdafvb8t9" +
                "CkKeVIg-ud9WZyQDc-NK1tneOpx87fKZaoqhrUoG4RySv3NwPJYiNgjIIzfZiNZ5" +
                "hyGHzTV3zi8bXt7Qt-pzIDn0QBciWHHpxGBGpxdQ74xu0K2mctwsnmJSi69FqNWh" +
                "Kekby0M-ZmBRw5d92ZfOWbYOslSUmI2dyDvNvojyNDPUFeWq1T8OaMYoAKe-CvXu" +
                "pZpLSGTzgDUZ23kG5aiKFYCiePGBeeYdhCuZq_ybwM0CI-kCfmfZW1L2o-nZshTu" +
                "SJxpnTcOVwzX_fkFVlN5dLwXCwLxhJNTJ7Vi5NnzS4Yp8NfY9iPkD97m76zLOMfI" +
                "nt50qhxoyEjRK_r-Afjcv-hzrqyp9Q_dontQMVM-y0ck1MKhwl7N4-3k29hy_T9O" +
                "fTF7qpV02RF36kVEeHZBLZN6ZlEkA89rib_IUj7wM6qWH3_m3NAELPCUhQ7jCBmn" +
                "CzTssElwwYqy7jbpmImdWq6JCRyIv_LUubGYmrUrYKpEfNKTMHjGMhNdOJlkjwDZ" +
                "ZqlPl6KvNcKe8xibAkHn1KCQxBH0SwIDAQABAoICAEaKicY2m8vJMMhKFY0k6YH-" +
                "EfJb_N7Y2txbWFc9wxD2ASPu-TntoDC8JgGiWQD1u27Vkl8SNwC_Uq0KxNcJnWLS" +
                "rdZ7-qppH1B9TgiW7KjeTzlI9q-pYK6CxhckS8vMErhforF1QZcNvkoPgTaM6ens" +
                "AF7Rd6hYfewAkdLGs0gUNLiNrfnE50SNuRNdC5Ne8NNlqtIDXMdUfZD3TJZYbgIS" +
                "oL9Ws09QvHxmt5wRjNHBF6eT9JLUMh--8QG69sKVuwwbScv0hN9YVLIvLYYKd76H" +
                "wCnh2Llm4g0_hm79to0Hb9msLoabTZyylxcJBJUQqngHs0bMv0z0R-2CX3he2VPd" +
                "rfrXEpX3UCpNu-BCmXxNNlfB65o8NtG_ro77RZrMAhMnr1H2Xrj-FdTE-Q5gs5oO" +
                "qp21wThoZs9SjDF1S6SiOyES47EfRE1a8gVTCAC7HAgtLNauj4ik_qDTuah1ucUr" +
                "gqu3f2ZaqWKxSVlYgewPPu9Xuwxgh2h0zv0a1dhT7OA7OC_Wn63KNgN7W2tr2CLN" +
                "G5jWY7L723nVnJjorWmc2FynpOhi6k2IQoJ-DPVpKpttAI6f-rCvAIuPe_EIyKG1" +
                "Pu_Em0To796_QLY-VstJoYscZwBd2ZH6ZTr1bwNSWHkp5nR9k05u108-WD03wtip" +
                "6cl8-iGcaIpqI67Oo-bdAoIBAQDnX-RxftNxrMjiOF54Qtj-9Qt25lR72C74s5aJ" +
                "Csci0jCBnhGyvrIQPYTufvgo5m2mqyEKjVJcOfprN9VpL3gZjfaDAq6Vl5WE6-Q-" +
                "cxF2B9rpX9Tuzo4Fmj83ReElidel9w7am4U3TbToyZ1h0pSOJftr3BhnmMcOlOIi" +
                "aplDawJ6THb03lkvV5JAwiAZR64TPGNv3njhkr295Hn1kIhMetZSzPGnEfbAbRmf" +
                "hwFLfobcE5xdIlK2EhpJdMS5ovKINVA6Fw2xEEaC6CYn4xPkVJTPafGVK8TZZie-" +
                "QFkAVsIk311oiftMiMK1K57d5RcE1hdXSdYUFpeVYmI30OT3AoIBAQDhVuWzt8wG" +
                "kg7ZVwc_4VMd0cT1qA_XMCvQ4wl6mIMITLUYXFEjkpFnLSntkAy34tGTPOqpM9De" +
                "Cbumtjj3HPd893ERNEkxlpfR2oY9L4XM6fQajCGxIbv5H1cLnsblJa_P5cKtRjYW" +
                "qrY4adU2qOrX6VGaJkvckJC3BjO4xGNlvRE_y-xfmShwQEfW7L8ehgdEhb8_F14G" +
                "bpyFz7ZzD4nGonecQwdkAsBBEgwPSnVF-4d7R3J1GwyGrtDHSEdaRsL_S-O3Hkep" +
                "PADApntAIGVUR_MI_mCtmsUtc_5mUqg-bJQqh5dnFsIwXZLZQyQaVvewPUedkkHg" +
                "Xn54_s0h5BpNAoIBAQCByT6Bk5zUFRISI4CKgSTrz1UA-y7E0X13sHVupgcSN0lS" +
                "S_Kti16i0X9xsPNPLgKwDSpZmvBqH3OjFQy3FhOOch2nW6fG7eLHTvMXPMC8rqdT" +
                "ZZgx5NexuNZhEOe8gNfglvdUFQzi-snSEtYfe1otaozf8fQWmJKAUW-P0q_qK2qW" +
                "Y7IOpXLtpXe6r6oFxDmXPLail-7Cyed5T2JCJzLtg7IZfDDJgMAjLI_E9pv5Vx4a" +
                "8T0y2QAAdaMdNUzsvMTDNvSrwSbC_dgvsj1E_pG38OIQfuMuxACF2lHM3JeQIxqA" +
                "SHNDIrM-OTDPI4rX-Zux8M3i_t4BIrMg7rEdkiX9AoIBACapLgfDhPGrpXiMgeXn" +
                "1sbK8qvjBbS5wwq3qSyrde-6mWdwj0s3HlNBYGwtxsDV3XcRgIE_LpqpuNRFd0iO" +
                "Y7fBDFkTS2uCltGeWGGvAZnCmerkF_O4AfQf-GM5_o3aBWv504i-_xCsgU70eWxD" +
                "VudsVF_KKkHRW8LLAZy1tQgDhC4Z4pgUQuffX3P0cmXeQOj0uXctnygjWh9rH7Zl" +
                "-BFoVnUs2tvBzRJc8ky9TZmQKhJwk6ab2W5SF-fY8sT-Vv5OGueT_l9-t_JVndfG" +
                "txvarEviuNuQLjw6Jm-PxuXO4yzYzpUVRoPdyhAUgOE0ApLuMJdMPJkuHSzNKoyi" +
                "AhECggEBAJgn1SBkJqfa6cgx7W2eEn8kp4wBpIuPjkFzJcJJ7LBbfmzCMKX8SBZR" +
                "cF2kOIOuM8TCFxkW5q8wRUTeqP2awgAMnYWeuxhJM0rzbVg3l6I1Lr1HIOxEExxE" +
                "Rr11Qtz3tXM6I2UVJyEF4hu3P1CsZeXJp8458jySwhC4J0Tir5sQ8fj2M0wOiwHY" +
                "XDY1A01EpicaeFv7882RHdlPUXXyHORvZ6vA8IVga_PyUovzmvmueOFp2HFmoqpP" +
                "Lbtiz8UgfYVsAyGAPiJpTOXT2YipLMeUb7MXdAon100pIxjrfatE7iJRs6jW0o4t" +
                "M7ctAhZ7IXQWuolas4ly8L0MABx9258=", "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy6nRmbQcpmdMszDwKbXg" +
                "5RHNIXoz91Xnu4vS_Fdtx8rWckGpOka5bAz0i4KZJ96fSFGen6TDejQ-Uzwr2Ihr" +
                "uvVJtTFB5RPZ94mRDyx87tRIYFB6WTJagMCWD6tQfwgNcroso3Wn72_LfQpCnlSI" +
                "PrnfVmckA3PjStbZ3jqcfO3ymWqKoa1KBuEckr9zcDyWIjYIyCM32YjWeYchh801" +
                "d84vG17e0LfqcyA59EAXIlhx6cRgRqcXUO-MbtCtpnLcLJ5iUouvRajVoSnpG8tD" +
                "PmZgUcOXfdmXzlm2DrJUlJiNncg7zb6I8jQz1BXlqtU_DmjGKACnvgr17qWaS0hk" +
                "84A1Gdt5BuWoihWAonjxgXnmHYQrmav8m8DNAiPpAn5n2VtS9qPp2bIU7kicaZ03" +
                "DlcM1_35BVZTeXS8FwsC8YSTUye1YuTZ80uGKfDX2PYj5A_e5u-syzjHyJ7edKoc" +
                "aMhI0Sv6_gH43L_oc66sqfUP3aJ7UDFTPstHJNTCocJezePt5NvYcv0_Tn0xe6qV" +
                "dNkRd-pFRHh2QS2TemZRJAPPa4m_yFI-8DOqlh9_5tzQBCzwlIUO4wgZpws07LBJ" +
                "cMGKsu426ZiJnVquiQkciL_y1LmxmJq1K2CqRHzSkzB4xjITXTiZZI8A2WapT5ei" +
                "rzXCnvMYmwJB59SgkMQR9EsCAwEAAQ=="
        ),
        ECCP256(
                KeyType.ECCP256, "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaEygF-BBlaq6Mk" +
                "mJuN4CTGYo2QPJZYadPjRhKPodCdyhRANCAAQA9NDknDc4Mor6mWKaW0zo3BLSwF8d1yNf4HCLn_zbw" +
                "vEkjuXo7-tob8faiZrixXoK7zuxip8yh86r-f0x1bFG", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD" +
                "QgAEAPTQ5Jw3ODKK-plimltM6NwS0sBfHdcjX-Bwi5_828LxJI7l6O_raG_H2oma4sV6Cu87sYqfMof" +
                "Oq_n9MdWxRg"
        ),
        ECCP384(
                KeyType.ECCP384, "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCqCSz-IHpchR9ffO" +
                "4TJKkxNiBg5Wlg2AK7u4ge_egQZC_qQdTxFZZp8wTHDMNzeaOhZANiAAQ9p9ePq4YY_MfPRQUfx_OPx" +
                "i1Ch6e4uIhgVYRUJYgW_kfZhyGRqlEnxXxbdBiCigPDHTWg0botpzmhGWfAmQ63v_2gluvB1sepqojT" +
                "TzKlvkGLYui_UZR0GVzyM1KSMww", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPafXj6uGGPzHz0UF" +
                "H8fzj8YtQoenuLiIYFWEVCWIFv5H2YchkapRJ8V8W3QYgooDwx01oNG6Lac5oRlnwJkOt7_9oJbrwdb" +
                "HqaqI008ypb5Bi2Lov1GUdBlc8jNSkjMM"
        ),
        ED25519(
                KeyType.ED25519, "MC4CAQAwBQYDK2VwBCIEIO_yEBZ291rK6lY8BH3RVtO61LnzLv78VxVxBZDj3uvi",
                "MCowBQYDK2VwAyEA7m2UD-6mR8vVSpGFFYCnsDgXTuFRT5_M7yVOMM_7uHw="
        ),
        X25519(
                KeyType.X25519, "MC4CAQAwBQYDK2VuBCIEIJjvGxF_sesDPC6uoIanoMQU-O4HGMpCqyBssnhc8yBS",
                "MCowBQYDK2VuAyEAq6Ws-klOFZ_Kbnf4TPqR45T9szGWeKz-5udDURxOeS4"
        );

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
                KeyFactory kf = KeyFactory.getInstance(
                        (keyType == KeyType.ED25519 || keyType == KeyType.X25519)
                                ? keyType.name()
                                : keyType.params.algorithm.name());
                return new KeyPair(
                        kf.generatePublic(new X509EncodedKeySpec(Base64.fromUrlSafeString(publicKey))),
                        kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.fromUrlSafeString(privateKey)))
                );
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static final String[] EC_SIGNATURE_ALGORITHMS = new String[]{"NONEwithECDSA", "SHA1withECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"};
    private static final String[] RSA_SIGNATURE_ALGORITHMS = new String[]{"NONEwithRSA", "MD5withRSA", "SHA1withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA"};
    private static final String[] RSA_CIPHER_ALGORITHMS = new String[]{"RSA/ECB/PKCS1Padding", "RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"};

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

    public static X509Certificate createCertificate(KeyPair keyPair) throws IOException, CertificateException {
        X500Name name = new X500Name("CN=Example");
        X509v3CertificateBuilder serverCertGen = new X509v3CertificateBuilder(
                name,
                new BigInteger("123456789"),
                new Date(),
                new Date(),
                name,
                SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()))
        );

        String algorithm;
        KeyType keyType = KeyType.fromKey(keyPair.getPrivate());
        switch (keyType.params.algorithm) {
            case EC:
                algorithm = keyType == KeyType.ED25519
                        ? "ED25519"
                        : "SHA256WithECDSA";
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

    public static void verify(PublicKey publicKey, Signature algorithm, byte[] signature) throws Exception {
        byte[] message = "Hello world".getBytes(StandardCharsets.UTF_8);
        algorithm.initVerify(publicKey);
        algorithm.update(message);
        boolean result = algorithm.verify(signature);
        Assert.assertTrue("Signature mismatch for " + algorithm.getAlgorithm(), result);
    }

    public static void rsaSignAndVerify(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        for (String algorithm : RSA_SIGNATURE_ALGORITHMS) {
            verify(publicKey, Signature.getInstance(algorithm), sign(privateKey, Signature.getInstance(algorithm)));
        }
    }

    public static void encryptAndDecrypt(PrivateKey privateKey, PublicKey publicKey, Cipher algorithm) throws Exception {
        byte[] message = "Hello world".getBytes(StandardCharsets.UTF_8);

        algorithm.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = algorithm.doFinal(message);

        algorithm = Cipher.getInstance(algorithm.getAlgorithm());
        algorithm.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = algorithm.doFinal(encrypted);

        Assert.assertArrayEquals("Decrypted mismatch", decrypted, message);
    }

    public static void rsaEncryptAndDecrypt(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        for (String algorithm : RSA_CIPHER_ALGORITHMS) {
            encryptAndDecrypt(privateKey, publicKey, Cipher.getInstance(algorithm));
        }
    }

    public static void rsaTests() throws Exception {
        for (KeyPair keyPair : new KeyPair[]{generateKey(KeyType.RSA1024), generateKey(KeyType.RSA2048), generateKey(KeyType.RSA3072), generateKey(KeyType.RSA4096)}) {
            rsaEncryptAndDecrypt(keyPair.getPrivate(), keyPair.getPublic());
            rsaSignAndVerify(keyPair.getPrivate(), keyPair.getPublic());
        }
    }

    public static void ecTests() throws Exception {
        for (KeyPair keyPair : new KeyPair[]{generateKey(KeyType.ECCP256), generateKey(KeyType.ECCP384)}) {
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
            logger.debug("Sign and verify test for {}", algorithm);
            verify(publicKey, Signature.getInstance(algorithm), sign(privateKey, Signature.getInstance(algorithm)));
        }
    }

    public static void ed25519SignAndVerify(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        String algorithm = "ED25519";
        logger.debug("Sign and verify test for Ed25519");
        verify(publicKey, Signature.getInstance(algorithm), sign(privateKey, Signature.getInstance(algorithm)));
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
    public static void x25519KeyAgreement(PrivateKey privateKey, PublicKey publicKey) throws Exception {
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

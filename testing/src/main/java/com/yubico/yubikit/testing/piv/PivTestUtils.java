/*
 * Copyright (C) 2020-2023 Yubico.
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

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.ManagementKeyType;
import com.yubico.yubikit.piv.PivSession;

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

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

@SuppressWarnings("SpellCheckingInspection")
public class PivTestUtils {

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
                KeyType.RSA4096, "MIIJQQIBADANBgkqhkiG9w0BAQEFAASCCSswggknAgEAAoICAQD0m4iO9RyDQf" +
                "GM4YTSs1L9oOocqYocC7VDi30Nt6UMRhguupbRlXVkNlz3urqhq0GjQVE_nnL0hjc2e0tinqYVXtjww" +
                "XcR5QKHLLv4DRzx18g8k-t1E6N5hJFys8dKd1-b5Ym_sxmhhiYRx5nudbiINY_OLiMK5kiILQGq5gw4" +
                "p_yGIDBdtrToNHLSXfJafWQjGeg0k2U5buvS86PBK3DvaBOq4wHuL35lPh7twJ8ttpuGr20aIzYYQ89" +
                "hsaIdLAodzUKkiK28cojgZ6QS35nozbXnCWqJrhJLytySjIFcQqvZrHBPUNSs34xXVD8H8jKh2oKe7Z" +
                "ECVB-Qa0TEIvOidPhLqzLV_kvDbxTPvUM4yvrrws3NCsBRDtfF8uqfEKVf-MkiI62hnQuq-mRMxn33J" +
                "z3e0_-0KDil-zxDq7psElS0y74JcwJYA91Z4NH_vTWrYMpqqtFfaHEU0vnJ5csAmq44LKeO2-JbDlJA" +
                "Rd3Pk7nAI7rDiILCNYkFD2JSQRnOMasdRe-mnrlXE3FmKFwUjuzK_TPz9_wn3USCHr08j4oSeEFYrpG" +
                "stuiGvhrobgpJmfh3oBBKskeKYF7VnGAjBwdv3yzJBe6l5oNDWykinWl4gihrgrXQgITQ9bDEIec148" +
                "6nxG46aV4thiMLuuhLlr0n1U0srItGbN2d2I-EaQIDAQABAoICAAei9ZuWoALM4QkM-d_3ngEh1X6aq" +
                "uoxpzbc1hptZ94BxWEWbXK33oPn9WqnsLUEfcPmZu5W6KpvvcMfTIpUybqGp7x1d8g43NA3okXYsp_Y" +
                "xM03sNegADVWdpGCNsK2sRxoKURRPRJnl8zr4mdZKMSPh9taofiwmZCvIgYR5k1cWOmJkU-oWSPGORR" +
                "OVKHaArwx-PzvjJmYoqIR00RqvNJWmXBBznu_OGxEqRkdr5fbuNA2w2_YAVPMMH9m7ljIORJ23UGkgZ" +
                "MNxYOcV2PznpBvyqyUD6Mif9BQB3yc8xrG-z_sQ_nanCHVCAKVHwjPw-BSdsvrfrYCm7_UdNTwQpL5q" +
                "-YGJplK95SoIyWalCiXvRvunKPaAZp1a177czZy6mDV_CKP86ySXWYmyRbddvzjDUKpo1DQ3kZGTkBs" +
                "zo884AgP-PtcLrpu3eNT2TODUw09LtDYTZe_C-0zpHywGNnEkTDHLBTNlTE51fCJW_dZKCYAczHUjFV" +
                "eIityMnuVMDgt-nqac4EEC2CEWKBXgC_QdR-ZGfmheVe2bSSoyeSGfFS3vM2v1nfxmZsKXba50oTM2-" +
                "RcpNtMrtgBEEtgV0o7sgTweitjy1yDiZiYqTgbAaSYVDvuIrVvfRzudqkm01IDRZmANrhm2v4_sti8k" +
                "RT8XfNBXfy5i4RJ-jFoIReRAoIBAQD70bTrQygAMgxDoK9HPNUtJ1aYa28PUeOTzttjJGlv6iZJ_3jE" +
                "lapO0-wv6NmwaNIV5AzJe--15hIlgndARrEFiN5RZEyEb3NlBVOUk3TW6X3tev5v0a8EvXaPoe8SOSl" +
                "0OR8Z5E1jr6_gn6xsLM_Nra__hu05oPp_D8DxnQgpxlIhqoTLIPxLuMk5pvJn-1lbJvEvhKyxpLNNFR" +
                "sq60SkIiJykHOAse2N6Iq2tygiV2Zi3mvU13dVdxItnVNKOSpgp6aWT99nh7OTw9RctDSygE_h8_LkH" +
                "oVhlrhf2Xc31l0AfbXfS8nOBDB9llecCyZ61RGD7fxbtIiritKPMQzZAoIBAQD4qyzzIEexnbTZPkjm" +
                "CWmJOr-fCfLXMFS8P6nG-XwUinBcjSEK8SJg2T3NAFwiu5061JfmM5JK01lziOu9PuoGYvwkxgohizW" +
                "0_IECt5-j4y8Nh2u3EWMkVT3hid8p8Gqf2tBCqibIanRKCDeRieo7gOusICiF51fEIL6RVoYEhTXLIq" +
                "o0DJPen37K9jx0G9BATumTrr0Ldzpeqo-xTrBnICfxMIgtQUoHd4d2bXZlyXImAQqbHLj1FShbge4C2" +
                "OcqkBDKen3H07cWJmqWfAx3K4r2gbs8Zs-lDWAg57k_sV6xHmTLO7BsjI9o6TzYcGDNfEVYD7tB0gCT" +
                "NBTPuLoRAoIBAEQaRs-Jbfv_jQmNH1oovY5koSq_g12lS-LhgruhUVKPBKPmj4a640BGWA3s71KiRo7" +
                "dCghDmGSdQDMcwZuEgsN4bIeelIMMkSy08BGyf1rP8tqS9NTQ5IBnrPTTWpCXHPrtp9ecwsE-9lXNWR" +
                "g4VkrNuldk6is3ugc6_3dYfKivle686wT0escPxnvtBonQlC3urjOnsfypCkTCfIJy9jFdeet53YLkm" +
                "9ZRGZKonhYLhQkgFhGN5BwdA7GKZsggBbH2JTtphoW9UXeY8onPwqCzyubUzs-a4X-u_1YMvg0_0A8d" +
                "8F3fZUhuIZ8VVcRBz7pQfVgsuJ8kiAG8nY1UOqECggEABpNYM_Glk6_M6XW5LcQP814HVShJMKGJjBT" +
                "O44ETY-OpRvlAZ26q7w6vkK0ywoRdiwG2JpM0ih_-nIyBV1bDj3msmzhVaj-pIukObEj4wreuNdhf48" +
                "5k5cAPS9h-ezhtSV7a5Phk4CXYf2CqP4H7HKmzEbEkAS515qzK_ULhdlsjagS3pXqzqk5jZvCN9rAJm" +
                "Lm9eXdEbnovo_M0q4aeKYvzInCbGT9BuuLRRTNtzxE9oH2kjyd6SJjPoWPVLGQZ8MkweHo2u0MA82f-" +
                "p44OMlSHby9NCTLayM2KvjQCdQm2rE5Wcf1ZE_W_kRGh10NZe_WOS97Wn83yz_GvnzKOUQKCAQAoLtg" +
                "0Ckv6pJKDGJIN7DzpobW-iFpYm8GY9kAX8LRT_uqAdrNPuyp9wTBgl3mDRqL0RtnKnOvWcOI9cRRPD7" +
                "mdQWF4J13wg018U1d6g81ohiHgMEdwTzEp8M-y7JTlsl0WBPYw0CGAr8NNfjOZLLlhqpBlGGMLCYj5e" +
                "kmqh0xqkNYyDTE5nRpWKcsINTwKg8fipZGeDpj5-b8CvDq5Qb_Ac0Br42MZmRTtWG-7TMdhiDyqMqlM" +
                "1PHCd2Oj4rRaVhvPfiaxUp0yG_prCg2TxoOw8RbHshnHvkLMpjuFKgj2S4QU3A0Z8DK_hOWFAn5z2OP" +
                "2IyPxlfOVbYi2a7QR-U-8", "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArXkknHlUgS" +
                "x9HV5uu0t4Jx_em1iTFNZRQKHkw2PvJutisWUfiwXvczVHAwe7-gXqi5bNzwxUSkOfbRNBNVxwNSV7-" +
                "sAfZj56xkaOE2ao_ixKr9zxoTyDiTcckO3KwsdjVMyKRZJBKWu50QXLkWQrf_H6iKkVjqJvsyy92Oc4" +
                "Ea4QlDivpkFWuzcaJgz27YzNs36LZi2Fk-adOIj24UY6RjXrpX7uPFkGTOif7GGQl3j0IqEVsprOXYv" +
                "pPWqbsB5nNs_dofpeQvnLG3UJzJ6yhX7B9-wiVGFzpviLy7Ma6jat91L_JA9ZKp2ycqs0_JdeTKjMo7" +
                "0v_Ba2OXCYqW3QyVPS6ZrpGCZSRF5IT_9UcXz34_DPykgF6f5gJjucO65fuS2qgwun5QAiTW6vU0hQa" +
                "8HYGyuIx2MEV2oysaC5vdXyU0bo6fi6wKiMH3NOW4HNz0LLpVyG4s8HWQDDaFEZWbD4g6ovWeZwV3XN" +
                "xQX-2crNjW9UBqSEobXl7IXdR87VZGP71KUYCvt-w62Wj3buTeE46nx-gLtJhjlxk1rXdl0WyxAHIFU" +
                "ml_PXNoSBkZ9nlUiw0aQUoPYNuKwV0SM71K_4Yh7LMRU_-W1-ZOTu9lIwatbhUAF86GItqKSOkgsXop" +
                "B3S8fg6EQWCnytizZUMwpgxvbgfw5Pmf1PRcYz42kCAwEAAQ=="
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
                KeyFactory kf = KeyFactory.getInstance(keyType.params.algorithm.name());
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
            case RSA1024:
            case RSA2048: //TODO Add 3072 and 4096
                return generateRsaKey(keyType.params.bitLength);
        }
        throw new IllegalArgumentException("Invalid algorithm");
    }

    private static KeyPair generateEcKey(String curve) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyType.Algorithm.EC.name());
            kpg.initialize(new ECGenParameterSpec(curve), new SecureRandom());
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
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
                algorithm = "SHA256WithECDSA";
                break;
            case RSA:
                algorithm = "SHA256WithRSA";
                break;
            default:
                throw new IllegalStateException();
        }
        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(keyPair.getPrivate());
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

    public static void ecSignAndVerify(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        for (String algorithm : EC_SIGNATURE_ALGORITHMS) {
            logger.debug("Test {}", algorithm);
            verify(publicKey, Signature.getInstance(algorithm), sign(privateKey, Signature.getInstance(algorithm)));
        }
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

    public static void authenticate(PivSession piv, byte[] key) throws BadResponseException, ApduException, IOException {
        piv.authenticate(getDefaultManagementKeyType(piv), key);
    }

    public static void setManagementKey(PivSession piv, byte[] key, boolean requireTouch) throws ApduException, IOException {
        piv.setManagementKey(getDefaultManagementKeyType(piv), key, requireTouch);
    }

    private static ManagementKeyType getDefaultManagementKeyType(PivSession piv) {
        return piv.getVersion().isAtLeast(5, 7, 0)
                ? ManagementKeyType.AES192
                : ManagementKeyType.TDES;
    }
}

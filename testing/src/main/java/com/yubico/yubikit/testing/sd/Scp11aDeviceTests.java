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

package com.yubico.yubikit.testing.sd;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.scp.KeyRef;
import com.yubico.yubikit.core.smartcard.scp.Scp03KeyParams;
import com.yubico.yubikit.core.smartcard.scp.Scp11KeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;
import com.yubico.yubikit.core.smartcard.scp.StaticKeys;
import com.yubico.yubikit.core.util.Tlv;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

public class Scp11aDeviceTests {

    static final KeyRef DEFAULT_SCP03_KEY = new KeyRef((byte) 0x01, (byte) 0xff);
    static final KeyRef AUTH_SCP03_KEY = new KeyRef((byte) 0x01, (byte) 0x01);
    static final KeyRef AUTH_SCP11A_KEY = new KeyRef(ScpKid.SCP11a, (byte) 2);
    static final KeyRef CA_KLOC_KEY_REF = new KeyRef((byte) 0x10, (byte) 2);

    @SuppressWarnings("SpellCheckingInspection")
    static final byte[] OCE_CERTS_V1 = ("-----BEGIN CERTIFICATE-----\n" +
            "MIIB8DCCAZegAwIBAgIUf0lxsK1R+EydqZKLLV/vXhaykgowCgYIKoZIzj0EAwIw\n" +
            "KjEoMCYGA1UEAwwfRXhhbXBsZSBPQ0UgUm9vdCBDQSBDZXJ0aWZpY2F0ZTAeFw0y\n" +
            "NDA1MjgwOTIyMDlaFw0yNDA4MjYwOTIyMDlaMC8xLTArBgNVBAMMJEV4YW1wbGUg\n" +
            "T0NFIEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49\n" +
            "AwEHA0IABMXbjb+Y33+GP8qUznrdZSJX9b2qC0VUS1WDhuTlQUfg/RBNFXb2/qWt\n" +
            "h/a+Ag406fV7wZW2e4PPH+Le7EwS1nyjgZUwgZIwHQYDVR0OBBYEFJzdQCINVBES\n" +
            "R4yZBN2l5CXyzlWsMB8GA1UdIwQYMBaAFDGqVWafYGfoHzPc/QT+3nPlcZ89MBIG\n" +
            "A1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgIEMCwGA1UdIAEB/wQiMCAw\n" +
            "DgYMKoZIhvxrZAAKAgEoMA4GDCqGSIb8a2QACgIBADAKBggqhkjOPQQDAgNHADBE\n" +
            "AiBE5SpNEKDW3OehDhvTKT9g1cuuIyPdaXGLZ3iX0x0VcwIgdnIirhlKocOKGXf9\n" +
            "ijkE8e+9dTazSPLf24lSIf0IGC8=\n" +
            "-----END CERTIFICATE-----\n" +
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIB2zCCAYGgAwIBAgIUSf59wIpCKOrNGNc5FMPTD9zDGVAwCgYIKoZIzj0EAwIw\n" +
            "KjEoMCYGA1UEAwwfRXhhbXBsZSBPQ0UgUm9vdCBDQSBDZXJ0aWZpY2F0ZTAeFw0y\n" +
            "NDA1MjgwOTIyMDlaFw0yNDA2MjcwOTIyMDlaMCoxKDAmBgNVBAMMH0V4YW1wbGUg\n" +
            "T0NFIFJvb3QgQ0EgQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n" +
            "AASPrxfpSB/AvuvLKaCz1YTx68Xbtx8S9xAMfRGwzp5cXMdF8c7AWpUfeM3BQ26M\n" +
            "h0WPvyBJKhCdeK8iVCaHyr5Jo4GEMIGBMB0GA1UdDgQWBBQxqlVmn2Bn6B8z3P0E\n" +
            "/t5z5XGfPTASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjA8BgNV\n" +
            "HSABAf8EMjAwMA4GDCqGSIb8a2QACgIBFDAOBgwqhkiG/GtkAAoCASgwDgYMKoZI\n" +
            "hvxrZAAKAgEAMAoGCCqGSM49BAMCA0gAMEUCIHv8cgOzxq2n1uZktL9gCXSR85mk\n" +
            "TieYeSoKZn6MM4rOAiEA1S/+7ez/gxDl01ztKeoHiUiW4FbEG4JUCzIITaGxVvM=\n" +
            "-----END CERTIFICATE-----").getBytes(StandardCharsets.UTF_8);

    // PKCS12 certificate with a private key and full certificate chain
    @SuppressWarnings("SpellCheckingInspection")
    public static byte[] OCE_V1 = Base64.fromUrlSafeString("MIIIfAIBAzCCCDIGCSqGSIb3DQEHAaCCCCME" +
            "gggfMIIIGzCCBtIGCSqGSIb3DQEHBqCCBsMwgga_AgEAMIIGuAYJKoZIhvcNAQcBMFcGCSqGSIb3DQEFDTB" +
            "KMCkGCSqGSIb3DQEFDDAcBAg8IcJO44iSgAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEAllIH" +
            "doQx_USA3jmRMeciiAggZQAHCPJ5lzPV0Z5tnssXZZ1AWm8AcKEq28gWUTVqVxc-0EcbKQHig1Jx7rqC3q4" +
            "G4sboIRw1vDH6q5O8eGsbkeNuYBim8fZ08JrsjeJABJoEiJrPqplMWA7H6a7athg3YSu1v4OR3UKN5Gyzn3" +
            "s0Yx5yMm_xzw204TEK5_1LpK8AMcUliFSq7jw3Xl1RY0zjMSWyQjX0KmB9IdubqQCfhy8zkKluAQADtHsEY" +
            "An0F3LoMETQytyUSkIvGMZoFemkCWV7zZ5n5IPhXL7gvnTu0WS8UxEnz_-FYdF43cjmwGfSb3OpaxOND4PB" +
            "CpwzbFfVCLa6mUBlwq1KQWRm1-PFm4LnL-3s2mxfjJAsVYP4U722_FHpW8rdTsyvdift9lsQjas2jIjCu8P" +
            "FClFZJLQldu5FxOhKzx2gsjYS_aeTdefwjlRiGtEFSrE1snKBbnBeRYFocBjhTD_sy3Vj0i5sbWwTx7iq67" +
            "joWydWAMp_lGSZ6akWRsyku_282jlwYsc3pR05qCHkbV0TzJcZofhXBwRgH5NKfulnJ1gH-i3e3RT3TauAK" +
            "lqCeAfvDvA3-jxEDy_puPncod7WH0m9P4OmXjZ0s5EI4U-v6bKPgL7LlTCEI6yj15P7kxmruoxZlDAmhixV" +
            "mlwJ8ZbVxD6Q-AOhXYPg-il3AYaRAS-VyJla0K-ac6hpYVAnbZCPzgHVkKC6iq4a_azf2b4uq9ks109jjnr" +
            "yAChdBsGdmStpZaPW4koMSAIJf12vGRp5jNjSaxaIL5QxTn0WCO8FHi1oqTmlTSWvR8wwZLiBmqQtnNTpew" +
            "iLL7C22lerUT7pYvKLCq_nnPYtb5UrSTHrmTNOUzEGVOSAGUWV293S4yiPGIwxT3dPE5_UaU_yKq1RonMRa" +
            "PhOZEESZEwLKVCqyDVEbAt7Hdahp-Ex0FVrC5JQhpVQ0Wn6uCptF2Jup70u-P2kVWjxrGBuRrlgEkKuHcoh" +
            "WoO9EMX_bLK9KcY4s1ofnfgSNagsAyX7N51Bmahgz1MCFOEcuFa375QYQhqkyLO2ZkNTpFQtjHjX0izZWO5" +
            "5LN3rNpcD9-fZt6ldoZCpg-t6y5xqHy-7soH0BpxF1oGIHAUkYSuXpLY0M7Pt3qqvsJ4_ycmFUEyoGv8Ib_" +
            "ieUBbebPz0Uhn-jaTpjgtKCyym7nBxVCuUv39vZ31nhNr4WaFsjdB_FOJh1s4KI6kQgzCSObrIVXBcLCTXP" +
            "fZ3jWxspKIREHn-zNuW7jIkbugSRiNFfVArcc7cmU4av9JPSmFiZzeyA0gkrkESTg8DVPT16u7W5HREX4Cw" +
            "mKu-12R6iYQ_po9Hcy6NJ8ShLdAzU0-q_BzgH7Cb8qimjgfGBA3Mesc-P98FlCzAjB2EgucRuXuehM_Femm" +
            "ZyNl0qI1Mj9qOgx_HeYaJaYD-yXwojApmetFGtDtMJsDxwL0zK7eGXeHHa7pd7OybKdSjDq25CCTOZvfR0D" +
            "D55FDIGCy0FsJTcferzPFlkz_Q45vEwuGfEBnXXS9IhH4ySvJmDmyfLMGiHW6t-9gjyEEg-dwSOq9yXYScf" +
            "CsefRl7-o_9nDoNQ8s_XS7LKlJ72ZEBaKeAxcm6q4wVwUWITNNl1R3EYAsFBWzYt4Ka9Ob3igVaNfeG9K4p" +
            "fQqMWcPpqVp4FuIsEpDWZYuv71s-WMYCs1JMfHbHDUczdRet1Ir2vLDGeWwvci70AzeKvvQ9OwBVESRec6c" +
            "Vrgt3EJWLey5sXY01WpMm526fwtLolSMpCf-dNePT97nXemQCcr3QXimagHTSGPngG3577FPrSQJl-lCJDY" +
            "xBFFtnd6hq4OcVr5HiNAbLnSjBWbzqxhHMmgoojy4rwtHmrfyVYKXyl-98r-Lobitv2tpnBqmjL6dMPRBOJ" +
            "vQl8-Wp4MGBsi1gvTgW_-pLlMXT--1iYyxBeK9_AN5hfjtrivewE3JY531jwkrl3rUl50MKwBJMMAtQQIYr" +
            "Dg7DAg_-QcOi-2mgo9zJPzR2jIXF0wP-9FA4-MITa2v78QVXcesh63agcFJCayGAL1StnbSBvvDqK5vEei3" +
            "uGZbeJEpU1hikQx57w3UzS9O7OSQMFvRBOrFBQsYC4JzfF0soIweGNpJxpm-UNYz-hB9vCb8-3OHA069M0C" +
            "AlJVOTF9uEpLVRzK-1kwggFBBgkqhkiG9w0BBwGgggEyBIIBLjCCASowggEmBgsqhkiG9w0BDAoBAqCB7zC" +
            "B7DBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIexxrwNlHM34CAggAMAwGCCqGSIb3DQIJBQAwHQ" +
            "YJYIZIAWUDBAEqBBAkK96h6gHJglyJl1_yEylvBIGQh62z7u5RoQ9y5wIXbE3_oMQTKVfCSrtqGUmj38sxD" +
            "Y7yIoTVQq7sw0MPNeYHROgGUAzawU0DlXMGuOWrbgzYeURZs0_HZ2Cqk8qhVnD8TgpB2n0U0NB7aJRHlkzT" +
            "l5MLFAwn3NE49CSzb891lGwfLYXYCfNfqltD7xZ7uvz6JAo_y6UtY8892wrRv4UdejyfMSUwIwYJKoZIhvc" +
            "NAQkVMRYEFJBU0s1_6SLbIRbyeq65gLWqClWNMEEwMTANBglghkgBZQMEAgEFAAQgqkOJRTcBlnx5yn57k2" +
            "3PH-qUXUGPEuYkrGy-DzEQiikECB0BXjHOZZhuAgIIAA==");
    public static char[] OCE_V1_PASSWORD = "password".toCharArray();

    @SuppressWarnings("SpellCheckingInspection")
    static final byte[] OCE_CERTS_V2 = ("-----BEGIN CERTIFICATE-----\n" +
            "MIICRTCCAeugAwIBAgICEAAwCgYIKoZIzj0EAwIwaDELMAkGA1UEBhMCU1YxCzAJ\n" +
            "BgNVBAgMAlNWMRIwEAYDVQQHDAlTdG9ja2hvbG0xEDAOBgNVBAoMB1Rlc3RPcmcx\n" +
            "FDASBgNVBAsMC1Rlc3RPcmdVbml0MRAwDgYDVQQDDAdDQS1LTE9DMCAXDTI0MDgw\n" +
            "MjA3NTI0MVoYDzIxMjQwNzA5MDc1MjQxWjBTMQswCQYDVQQGEwJTVjELMAkGA1UE\n" +
            "CAwCU1YxEDAOBgNVBAoMB1Rlc3RPcmcxFDASBgNVBAsMC1Rlc3RPcmdVbml0MQ8w\n" +
            "DQYDVQQDDAZDQS1PQ0UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARQ8mUZsuiR\n" +
            "njsqLh8WMPz2CB6rhF7FZhLNqBQCEBT9yP2TPSqtSizYj0IBnYVFpNEo+e70dU7F\n" +
            "3VmjkbuEXMTAo4GXMIGUMB8GA1UdIwQYMBaAFHMPyjll59Oc2tkOYx70pZ0u6JcJ\n" +
            "MAsGA1UdDwQEAwIDCDAZBgNVHSAEEjAQMA4GDCqGSIb8a2QACgIBADAUBgwqhkiG\n" +
            "/GtkAAoCAAEEBAQCvyAwFAYMKoZIhvxrZAAKAgACBAQEAl8gMB0GA1UdDgQWBBTv\n" +
            "xZlvtJr2cz2ZOX+fjOyJKKIUzDAKBggqhkjOPQQDAgNIADBFAiBlnbco6Ciwf+3Y\n" +
            "EyK8ZU07zeQPp47+XUEfgPF1qL9TgwIhANSqEpSjoMJTpFO8gzOey+Q83mXOiCRp\n" +
            "c6go7DG5ObQh\n" +
            "-----END CERTIFICATE-----\n"
            + "-----BEGIN CERTIFICATE-----\n" +
            "MIICLjCCAdSgAwIBAgIUOhaGJ8+QFxtHCXhvLRGhJY/wq7wwCgYIKoZIzj0EAwIw\n" +
            "aDELMAkGA1UEBhMCU1YxCzAJBgNVBAgMAlNWMRIwEAYDVQQHDAlTdG9ja2hvbG0x\n" +
            "EDAOBgNVBAoMB1Rlc3RPcmcxFDASBgNVBAsMC1Rlc3RPcmdVbml0MRAwDgYDVQQD\n" +
            "DAdDQS1LTE9DMCAXDTI0MDgwMjA3NTE1MFoYDzIyMjQwNjE1MDc1MTUwWjBoMQsw\n" +
            "CQYDVQQGEwJTVjELMAkGA1UECAwCU1YxEjAQBgNVBAcMCVN0b2NraG9sbTEQMA4G\n" +
            "A1UECgwHVGVzdE9yZzEUMBIGA1UECwwLVGVzdE9yZ1VuaXQxEDAOBgNVBAMMB0NB\n" +
            "LUtMT0MwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATRC0DYFzG0Lm0TwekgXYPz\n" +
            "2ScKOARoft2t/E4WUyFiX0Snsy6S2y+hYP+bscnjUEKZplxE91MlsBNVhG09ZMx3\n" +
            "o1owWDAdBgNVHQ4EFgQUcw/KOWXn05za2Q5jHvSlnS7olwkwCwYDVR0PBAQDAgEG\n" +
            "MA8GA1UdEwEB/wQFMAMBAf8wGQYDVR0gBBIwEDAOBgwqhkiG/GtkAAoCARQwCgYI\n" +
            "KoZIzj0EAwIDSAAwRQIhAPhg4A/O3RNNiBniSAzenpE1ftkaKSk21oMd95XKwdqb\n" +
            "AiBzSpZzDimTeD/24luQ27oAOAmPI808aX8YMctqlo0LEg==\n" +
            "-----END CERTIFICATE-----\n").getBytes(StandardCharsets.UTF_8);

    @SuppressWarnings("SpellCheckingInspection")
    public static byte[] OCE_V2 = Base64.fromUrlSafeString("MIIE7AIBAzCCBKIGCSqGSIb3DQEHAaCCBJME" +
            "ggSPMIIEizCCAzoGCSqGSIb3DQEHBqCCAyswggMnAgEAMIIDIAYJKoZIhvcNAQcBMF8GCSqGSIb3DQEFDTB" +
            "SMDEGCSqGSIb3DQEFDDAkBBAn11qHSzbFWry2uT9sm1TkAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAw" +
            "QBKgQQyd4c6OQQ_iirEEQOSE9XoYCCArDY1YqqfjynV3J09obO-_0WDGjJ-isRyYXbpRwOrw3r8-m7TmN1a" +
            "nC7t0Gwb-Do2y3gbX54pko8lXY0rUyT0GTC1fr820Ghi72ovO6rr9JwSv2ndjOe-A4e65aisjMlHPZKJi1y" +
            "YWsV9dJzO6OO75nnauX6SCeYCMTWzRKMZj7NHPaGFsl_jyaEqxAteY5tXYudzGmOYLIcSPMj_r0QbfL_Fo8" +
            "DtkI6DcXOSVQnu-fHQl8SZAN-6qZ2eQr4TdsS3njn4gscgqsXnKw0FIhv3Js7ab89WHpLrjPHW31RJPSPWc" +
            "vTFgMRb4O_2OmEm7aiwj4YnvBdnxtYmeCi5lbthZxW3MFu72DEAZQsnXvflGaV29rafUhKgwWWbiUvX0f4r" +
            "XIUrfbQ1udf1I5l7LNC7RMwHYsObSOwoX6dDzj1kGroz1B_MeiIznT0RAd-YvLZ1SQM99MB8_gktWyJUO1e" +
            "HjF4faBHgGAGCA0svdryKgy7D7TzvS2TjNOTWaJvRlaxzFmerXTmZytnDEbkU9eVyiiPR37KcpD2_KiLJzn" +
            "vWKSo3wImP9-MPnxwNrkEcKf4qHZaE3ky_WLbnC2R8K5odIt7_01A0Nm-f-1NbuxtZBLy6tKnYUf3ir_PPm" +
            "pjphS-D3coHn4Tlfa_chGNsMnP-TWDkxCgCyxHDvotpIynHxAibS9GHGHDF6nJekS9cFkGLJ9axJg2Pygic" +
            "g78ls-CcDeAllFT46sU1d8Pz9A9MhJYmKc-AWBM00r9P32JC7kAANbOWErgUDwsRMxxHqVDo1U7QTL8LkBI" +
            "CmVkpqzF7ObxwU04PB7E0k22sMp1zg95foVst3rZHriJ85CPq7Ht2ZsyLKmJNgqTfkgEJ_kVMuRRRcs4Pod" +
            "4aHZL40qy6qrMru-qPTnVD0_2kV59W3xbd_ybMIIBSQYJKoZIhvcNAQcBoIIBOgSCATYwggEyMIIBLgYLKo" +
            "ZIhvcNAQwKAQKggfcwgfQwXwYJKoZIhvcNAQUNMFIwMQYJKoZIhvcNAQUMMCQEEI2wPOcHSnElmbOyeO0dj" +
            "bACAggAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBDH2f8UV8_hw3QAA7KO6WCYBIGQF6lkbV6ZPhC-" +
            "s0WB-25i_Q6uPFieZsmqBsLHoVzXE8US_Kz4YitiVkVPY8JAcJSMI6DcQVkGPJW7suipx2evtne9kJI8TYh" +
            "VsX0g7pv3HyTg2roDlHCbedoRHZcoC8lqy078LSdJicJmRLN0aj417oxRbMm972_pCHajk60hhA2A_fDoLA" +
            "bEPJoO1qdFcjCjMSUwIwYJKoZIhvcNAQkVMRYEFOgid7IToNeY7_auRfGdSPhz0f-yMEEwMTANBglghkgBZ" +
            "QMEAgEFAAQggxlm83v4OwO2nvegRpOK2G4HvCi0iO31XksWx0Pf5DkECAqUVhzeEdSPAgIIAA==");
    public static char[] OCE_V2_PASSWORD = "password".toCharArray();

    public static void testImportKey(SecurityDomainTestState state) throws Throwable {
        testImportKey(state, OCE_CERTS_V1, OCE_V1, OCE_V1_PASSWORD);
    }

    public static void testImportKeyAlt(SecurityDomainTestState state) throws Throwable {
        testImportKey(state, OCE_CERTS_V2, OCE_V2, OCE_V2_PASSWORD);
    }

    public static void testImportKey(
            SecurityDomainTestState state,
            byte[] oceCerts,
            byte[] oce,
            char[] password) throws Throwable {

        assumeTrue("Device does not support SCP11a", state.getDeviceInfo().getVersion()
                .isAtLeast(5, 7, 2));

        state.withSecurityDomain(SecurityDomainSession::reset);

        // replace default SCP03 keys so that we can authenticate later
        ScpKeyParams scp03KeyParams = importNewScp03Key(state);

        PublicKeyValues pk = state.withSecurityDomain(scp03KeyParams, sd -> {
            return setupScp11a(sd, oceCerts);
        });

        // direct auth
        state.withSecurityDomain(
                getScp11aKeyParams(oce, password, pk.toPublicKey()),
                sd -> {
                    Map<KeyRef, Map<Byte, Byte>> keyInformation = sd.getKeyInformation();
                    assertNotNull(keyInformation.get(AUTH_SCP11A_KEY));
                });

        // read public key and auth
        state.withSecurityDomain(sd -> {
            List<X509Certificate> certs = sd.getCertificateBundle(AUTH_SCP11A_KEY);
            PublicKey publicKey = certs.get(certs.size() - 1).getPublicKey();
            ScpKeyParams params = getScp11aKeyParams(oce, password, publicKey);
            sd.authenticate(params);
            // use authenticated session to make a request
            Map<KeyRef, Map<Byte, Byte>> keyInformation = sd.getKeyInformation();
            assertNotNull(keyInformation.get(AUTH_SCP11A_KEY));
        });

        // read public key and then auth
        PublicKey publicKey = state.withSecurityDomain(sd -> {
            List<X509Certificate> certs = sd.getCertificateBundle(AUTH_SCP11A_KEY);
            return certs.get(certs.size() - 1).getPublicKey();
        });

        state.withSecurityDomain(
                getScp11aKeyParams(oce, password, publicKey),
                sd -> {
                    // use authenticated session to make a request
                    Map<KeyRef, Map<Byte, Byte>> keyInformation = sd.getKeyInformation();
                    assertNotNull(keyInformation.get(AUTH_SCP11A_KEY));
                });
    }

    private static ScpKeyParams importNewScp03Key(SecurityDomainTestState state) throws Throwable {
        final byte[] sk = new byte[]{
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        };
        final StaticKeys staticKeys = new StaticKeys(sk, sk, sk);

        assumeFalse("SCP03 not supported over NFC on FIPS capable devices",
                state.getDeviceInfo().getFipsCapable() != 0 && !state.isUsbTransport());

        state.withSecurityDomain(sd -> {
            sd.authenticate(new Scp03KeyParams(DEFAULT_SCP03_KEY, StaticKeys.getDefaultKeys()));
            sd.putKey(AUTH_SCP03_KEY, staticKeys, 0);
        });

        return new Scp03KeyParams(AUTH_SCP03_KEY, staticKeys);
    }

    private static Scp11KeyParams getScp11aKeyParams(byte[] pkcs12, char[] password, PublicKey pk)
            throws Throwable {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try (InputStream is = new ByteArrayInputStream(pkcs12)) {
            keyStore.load(is, password);

            final Enumeration<String> aliases = keyStore.aliases();
            assertTrue(aliases.hasMoreElements());
            String alias = keyStore.aliases().nextElement();
            assertTrue(keyStore.isKeyEntry(alias));

            Key sk = keyStore.getKey(keyStore.aliases().nextElement(), password);
            assertTrue("No private key in pkcs12", sk instanceof PrivateKey);

            ScpCertificates certs = ScpCertificates.from(getCertificateChain(keyStore, alias));

            List<X509Certificate> certChain = new ArrayList<>(certs.bundle);
            if (certs.leaf != null) {
                certChain.add(certs.leaf);
            }

            return new Scp11KeyParams(
                    AUTH_SCP11A_KEY,
                    pk,
                    CA_KLOC_KEY_REF,
                    (PrivateKey) sk,
                    certChain
            );
        }
    }

    @SuppressWarnings("unchecked")
    private static ScpCertificates getOceCertificates(byte[] pem)
            throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try (InputStream is = new ByteArrayInputStream(pem)) {
            return ScpCertificates.from((List<X509Certificate>) certificateFactory.generateCertificates(is));
        }
    }

    private static byte[] getSki(X509Certificate certificate) {
        byte[] skiExtensionValue = certificate.getExtensionValue("2.5.29.14");
        if (skiExtensionValue == null) {
            return null;
        }
        assertNotNull("Missing Subject Key Identifier", skiExtensionValue);
        Tlv tlv = Tlv.parse(skiExtensionValue);
        assertEquals("Invalid extension value", 0x04, tlv.getTag());
        Tlv digest = Tlv.parse(tlv.getValue());
        assertEquals("Invalid Subject Key Identifier", 0x04, digest.getTag());
        return digest.getValue();
    }

    private static List<X509Certificate> getCertificateChain(KeyStore keyStore, String alias)
            throws KeyStoreException {
        Certificate[] chain = keyStore.getCertificateChain(alias);
        final List<X509Certificate> certificateChain = new ArrayList<>();
        for (Certificate cert : chain) {
            if (cert instanceof X509Certificate) {
                certificateChain.add((X509Certificate) cert);
            }
        }
        return certificateChain;
    }

    private static PublicKeyValues setupScp11a(SecurityDomainSession sd, byte[] pem)
            throws Throwable {
        // generate new SCP11a key
        PublicKeyValues generatedPk = sd.generateEcKey(AUTH_SCP11A_KEY, 0);

        // delete default SCP11b key
        sd.deleteKey(new KeyRef(ScpKid.SCP11b, (byte) 1), false);

        // import OCE CA-KLOC certificate
        ScpCertificates certs = getOceCertificates(pem);

        if (certs.ca == null) {
            fail("Input does not contain valid CA-KLOC certificate");
        }

        sd.putKey(CA_KLOC_KEY_REF, PublicKeyValues.fromPublicKey(certs.ca.getPublicKey()), 0);

        byte[] ski = getSki(certs.ca);
        assertNotNull("CA certificate missing Subject Key Identifier", ski);
        sd.storeCaIssuer(CA_KLOC_KEY_REF, ski);

        // delete our SCP03 keys
        sd.deleteKey(AUTH_SCP03_KEY, false);

        return generatedPk;
    }
}

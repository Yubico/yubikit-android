/*
 * Copyright (C) 2024 Yubico.
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

import com.yubico.yubikit.core.internal.codec.Base64;

import java.nio.charset.StandardCharsets;

class Scp11TestData {
    @SuppressWarnings("SpellCheckingInspection")
    static final byte[] OCE_CERTS = ("-----BEGIN CERTIFICATE-----\n" +
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
    static byte[] OCE = Base64.fromUrlSafeString("MIIIfAIBAzCCCDIGCSqGSIb3DQEHAaCCCCMEgggfMIIIGz" +
            "CCBtIGCSqGSIb3DQEHBqCCBsMwgga_AgEAMIIGuAYJKoZIhvcNAQcBMFcGCSqGSIb3DQEFDTBKMCkGCSqGS" +
            "Ib3DQEFDDAcBAg8IcJO44iSgAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEAllIHdoQx_USA3j" +
            "mRMeciiAggZQAHCPJ5lzPV0Z5tnssXZZ1AWm8AcKEq28gWUTVqVxc-0EcbKQHig1Jx7rqC3q4G4sboIRw1v" +
            "DH6q5O8eGsbkeNuYBim8fZ08JrsjeJABJoEiJrPqplMWA7H6a7athg3YSu1v4OR3UKN5Gyzn3s0Yx5yMm_x" +
            "zw204TEK5_1LpK8AMcUliFSq7jw3Xl1RY0zjMSWyQjX0KmB9IdubqQCfhy8zkKluAQADtHsEYAn0F3LoMET" +
            "QytyUSkIvGMZoFemkCWV7zZ5n5IPhXL7gvnTu0WS8UxEnz_-FYdF43cjmwGfSb3OpaxOND4PBCpwzbFfVCL" +
            "a6mUBlwq1KQWRm1-PFm4LnL-3s2mxfjJAsVYP4U722_FHpW8rdTsyvdift9lsQjas2jIjCu8PFClFZJLQld" +
            "u5FxOhKzx2gsjYS_aeTdefwjlRiGtEFSrE1snKBbnBeRYFocBjhTD_sy3Vj0i5sbWwTx7iq67joWydWAMp_" +
            "lGSZ6akWRsyku_282jlwYsc3pR05qCHkbV0TzJcZofhXBwRgH5NKfulnJ1gH-i3e3RT3TauAKlqCeAfvDvA" +
            "3-jxEDy_puPncod7WH0m9P4OmXjZ0s5EI4U-v6bKPgL7LlTCEI6yj15P7kxmruoxZlDAmhixVmlwJ8ZbVxD" +
            "6Q-AOhXYPg-il3AYaRAS-VyJla0K-ac6hpYVAnbZCPzgHVkKC6iq4a_azf2b4uq9ks109jjnryAChdBsGdm" +
            "StpZaPW4koMSAIJf12vGRp5jNjSaxaIL5QxTn0WCO8FHi1oqTmlTSWvR8wwZLiBmqQtnNTpewiLL7C22ler" +
            "UT7pYvKLCq_nnPYtb5UrSTHrmTNOUzEGVOSAGUWV293S4yiPGIwxT3dPE5_UaU_yKq1RonMRaPhOZEESZEw" +
            "LKVCqyDVEbAt7Hdahp-Ex0FVrC5JQhpVQ0Wn6uCptF2Jup70u-P2kVWjxrGBuRrlgEkKuHcohWoO9EMX_bL" +
            "K9KcY4s1ofnfgSNagsAyX7N51Bmahgz1MCFOEcuFa375QYQhqkyLO2ZkNTpFQtjHjX0izZWO55LN3rNpcD9" +
            "-fZt6ldoZCpg-t6y5xqHy-7soH0BpxF1oGIHAUkYSuXpLY0M7Pt3qqvsJ4_ycmFUEyoGv8Ib_ieUBbebPz0" +
            "Uhn-jaTpjgtKCyym7nBxVCuUv39vZ31nhNr4WaFsjdB_FOJh1s4KI6kQgzCSObrIVXBcLCTXPfZ3jWxspKI" +
            "REHn-zNuW7jIkbugSRiNFfVArcc7cmU4av9JPSmFiZzeyA0gkrkESTg8DVPT16u7W5HREX4CwmKu-12R6iY" +
            "Q_po9Hcy6NJ8ShLdAzU0-q_BzgH7Cb8qimjgfGBA3Mesc-P98FlCzAjB2EgucRuXuehM_FemmZyNl0qI1Mj" +
            "9qOgx_HeYaJaYD-yXwojApmetFGtDtMJsDxwL0zK7eGXeHHa7pd7OybKdSjDq25CCTOZvfR0DD55FDIGCy0" +
            "FsJTcferzPFlkz_Q45vEwuGfEBnXXS9IhH4ySvJmDmyfLMGiHW6t-9gjyEEg-dwSOq9yXYScfCsefRl7-o_" +
            "9nDoNQ8s_XS7LKlJ72ZEBaKeAxcm6q4wVwUWITNNl1R3EYAsFBWzYt4Ka9Ob3igVaNfeG9K4pfQqMWcPpqV" +
            "p4FuIsEpDWZYuv71s-WMYCs1JMfHbHDUczdRet1Ir2vLDGeWwvci70AzeKvvQ9OwBVESRec6cVrgt3EJWLe" +
            "y5sXY01WpMm526fwtLolSMpCf-dNePT97nXemQCcr3QXimagHTSGPngG3577FPrSQJl-lCJDYxBFFtnd6hq" +
            "4OcVr5HiNAbLnSjBWbzqxhHMmgoojy4rwtHmrfyVYKXyl-98r-Lobitv2tpnBqmjL6dMPRBOJvQl8-Wp4MG" +
            "Bsi1gvTgW_-pLlMXT--1iYyxBeK9_AN5hfjtrivewE3JY531jwkrl3rUl50MKwBJMMAtQQIYrDg7DAg_-Qc" +
            "Oi-2mgo9zJPzR2jIXF0wP-9FA4-MITa2v78QVXcesh63agcFJCayGAL1StnbSBvvDqK5vEei3uGZbeJEpU1" +
            "hikQx57w3UzS9O7OSQMFvRBOrFBQsYC4JzfF0soIweGNpJxpm-UNYz-hB9vCb8-3OHA069M0CAlJVOTF9uE" +
            "pLVRzK-1kwggFBBgkqhkiG9w0BBwGgggEyBIIBLjCCASowggEmBgsqhkiG9w0BDAoBAqCB7zCB7DBXBgkqh" +
            "kiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIexxrwNlHM34CAggAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUD" +
            "BAEqBBAkK96h6gHJglyJl1_yEylvBIGQh62z7u5RoQ9y5wIXbE3_oMQTKVfCSrtqGUmj38sxDY7yIoTVQq7" +
            "sw0MPNeYHROgGUAzawU0DlXMGuOWrbgzYeURZs0_HZ2Cqk8qhVnD8TgpB2n0U0NB7aJRHlkzTl5MLFAwn3N" +
            "E49CSzb891lGwfLYXYCfNfqltD7xZ7uvz6JAo_y6UtY8892wrRv4UdejyfMSUwIwYJKoZIhvcNAQkVMRYEF" +
            "JBU0s1_6SLbIRbyeq65gLWqClWNMEEwMTANBglghkgBZQMEAgEFAAQgqkOJRTcBlnx5yn57k23PH-qUXUGP" +
            "EuYkrGy-DzEQiikECB0BXjHOZZhuAgIIAA==");
    static char[] OCE_PASSWORD = "password".toCharArray();
}

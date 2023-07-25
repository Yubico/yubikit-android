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

package com.yubico.yubikit.openpgp;

public class Do {
    public static final int PRIVATE_USE_1 = 0x0101;
    public static final int PRIVATE_USE_2 = 0x0102;
    public static final int PRIVATE_USE_3 = 0x0103;
    public static final int PRIVATE_USE_4 = 0x0104;
    public static final int AID = 0x4F;
    public static final int NAME = 0x5B;
    public static final int LOGIN_DATA = 0x5E;
    public static final int LANGUAGE = 0xEF2D;
    public static final int SEX = 0x5F35;
    public static final int URL = 0x5F50;
    public static final int HISTORICAL_BYTES = 0x5F52;
    public static final int EXTENDED_LENGTH_INFO = 0x7F66;
    public static final int GENERAL_FEATURE_MANAGEMENT = 0x7F74;
    public static final int CARDHOLDER_RELATED_DATA = 0x65;
    public static final int APPLICATION_RELATED_DATA = 0x6E;
    public static final int ALGORITHM_ATTRIBUTES_SIG = 0xC1;
    public static final int ALGORITHM_ATTRIBUTES_DEC = 0xC2;
    public static final int ALGORITHM_ATTRIBUTES_AUT = 0xC3;
    public static final int ALGORITHM_ATTRIBUTES_ATT = 0xDA;
    public static final int PW_STATUS_BYTES = 0xC4;
    public static final int FINGERPRINT_SIG = 0xC7;
    public static final int FINGERPRINT_DEC = 0xC8;
    public static final int FINGERPRINT_AUT = 0xC9;
    public static final int FINGERPRINT_ATT = 0xDB;
    public static final int CA_FINGERPRINT_1 = 0xCA;
    public static final int CA_FINGERPRINT_2 = 0xCB;
    public static final int CA_FINGERPRINT_3 = 0xCC;
    public static final int CA_FINGERPRINT_4 = 0xDC;
    public static final int GENERATION_TIME_SIG = 0xCE;
    public static final int GENERATION_TIME_DEC = 0xCF;
    public static final int GENERATION_TIME_AUT = 0xD0;
    public static final int GENERATION_TIME_ATT = 0xDD;
    public static final int RESETTING_CODE = 0xD3;
    public static final int UIF_SIG = 0xD6;
    public static final int UIF_DEC = 0xD7;
    public static final int UIF_AUT = 0xD8;
    public static final int UIF_ATT = 0xD9;
    public static final int SECURITY_SUPPORT_TEMPLATE = 0x7A;
    public static final int CARDHOLDER_CERTIFICATE = 0x7F21;
    public static final int KDF = 0xF9;
    public static final int ALGORITHM_INFORMATION = 0xFA;
    public static final int ATT_CERTIFICATE = 0xFC;
}

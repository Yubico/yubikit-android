/*
 * Copyright (C) 2019 Yubico.
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

public class ObjectData {
    public static final byte[] CAPABILITY = new byte[] {0x5f, (byte)0xc1, 0x07};
    public static final byte[] CHUID = new byte[] {0x5f, (byte)0xc1, 0x02};
    public static final byte[] AUTHENTICATION = new byte[] {0x5f, (byte)0xc1, 0x05};  // cert for 9a key
    public static final byte[] FINGERPRPRINTS = new byte[] {0x5f, (byte)0xc1, 0x03};
    public static final byte[] SECURITY = new byte[] {0x5f, (byte)0xc1, 0x06};
    public static final byte[] FACIAL = new byte[] {0x5f, (byte)0xc1, 0x08};
    public static final byte[] SIGNATURE = new byte[] {0x5f, (byte)0xc1, 0x0a};  // cert for 9c key
    public static final byte[] KEY_MANAGEMENT = new byte[] {0x5f, (byte)0xc1, 0x0b};  // cert for 9d key
    public static final byte[] CARD_AUTH = new byte[] {0x5f, (byte)0xc1, 0x01}; // cert for 9e key
    public static final byte[] DISCOVERY = new byte[] {0x7e};
    public static final byte[] KEY_HISTORY = new byte[] {0x5f, (byte)0xc1, 0x0c};
    public static final byte[] IRIS = new byte[] {0x5f, (byte)0xc1, 0x21};

    public static final byte[] RETIRED1 = new byte[] {0x5f, (byte)0xc1, 0x0d};
    public static final byte[] RETIRED2 = new byte[] {0x5f, (byte)0xc1, 0x0e};
    public static final byte[] RETIRED3 = new byte[] {0x5f, (byte)0xc1, 0x0f};
    public static final byte[] RETIRED4 = new byte[] {0x5f, (byte)0xc1, 0x10};
    public static final byte[] RETIRED5 = new byte[] {0x5f, (byte)0xc1, 0x11};
    public static final byte[] RETIRED6 = new byte[] {0x5f, (byte)0xc1, 0x12};
    public static final byte[] RETIRED7 = new byte[] {0x5f, (byte)0xc1, 0x13};
    public static final byte[] RETIRED8 = new byte[] {0x5f, (byte)0xc1, 0x14};
    public static final byte[] RETIRED9 = new byte[] {0x5f, (byte)0xc1, 0x15};
    public static final byte[] RETIRED10 = new byte[] {0x5f, (byte)0xc1, 0x16};
    public static final byte[] RETIRED11 = new byte[] {0x5f, (byte)0xc1, 0x17};
    public static final byte[] RETIRED12 = new byte[] {0x5f, (byte)0xc1, 0x18};
    public static final byte[] RETIRED13 = new byte[] {0x5f, (byte)0xc1, 0x19};
    public static final byte[] RETIRED14 = new byte[] {0x5f, (byte)0xc1, 0x1a};
    public static final byte[] RETIRED15 = new byte[] {0x5f, (byte)0xc1, 0x1b};
    public static final byte[] RETIRED16 = new byte[] {0x5f, (byte)0xc1, 0x1c};
    public static final byte[] RETIRED17 = new byte[] {0x5f, (byte)0xc1, 0x1d};
    public static final byte[] RETIRED18 = new byte[] {0x5f, (byte)0xc1, 0x1e};
    public static final byte[] RETIRED19 = new byte[] {0x5f, (byte)0xc1, 0x1f};
    public static final byte[] RETIRED20 = new byte[] {0x5f, (byte)0xc1, 0x20};

    public static final byte[] PIVMAN_DATA = new byte[] {0x5f , (byte)0xff, 0x00};
    public static final byte[] PIVMAN_PROTECTED_DATA = new byte[] {0x5f, (byte)0xc1, 0x09}; // Use slot for printed information.
    public static final byte[] ATTESTATION = new byte[] {0x5f , (byte)0xff, 0x01};
}

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

/**
 * Slots of YubiKey
 * 9a is for PIV Authentication
 * 9c is for Digital Signature (PIN always checked)
 * 9d is for Key Management
 * 9e is for Card Authentication (PIN never checked)
 * 82-95 is for Retired Key Management
 * f9 is for Attestation
 */
public enum Slot {
    AUTHENTICATION(0x9a, ObjectData.AUTHENTICATION),
    CARD_MANAGEMENT(0x9b, null),
    SIGNATURE(0x9c, ObjectData.SIGNATURE),
    KEY_MANAGEMENT(0x9d, ObjectData.KEY_MANAGEMENT),
    CARD_AUTH(0x9e, ObjectData.CARD_AUTH),

    RETIRED1(0x82, ObjectData.RETIRED1),
    RETIRED2(0x83, ObjectData.RETIRED2),
    RETIRED3(0x84, ObjectData.RETIRED3),
    RETIRED4(0x85, ObjectData.RETIRED4),
    RETIRED5(0x86, ObjectData.RETIRED5),
    RETIRED6(0x87, ObjectData.RETIRED6),
    RETIRED7(0x88, ObjectData.RETIRED7),
    RETIRED8(0x89, ObjectData.RETIRED8),
    RETIRED9(0x8a, ObjectData.RETIRED9),
    RETIRED10(0x8b, ObjectData.RETIRED10),
    RETIRED11(0x8c, ObjectData.RETIRED11),
    RETIRED12(0x8d, ObjectData.RETIRED12),
    RETIRED13(0x8e, ObjectData.RETIRED13),
    RETIRED14(0x8f, ObjectData.RETIRED14),
    RETIRED15(0x90, ObjectData.RETIRED15),
    RETIRED16(0x91, ObjectData.RETIRED16),
    RETIRED17(0x92, ObjectData.RETIRED17),
    RETIRED18(0x93, ObjectData.RETIRED18),
    RETIRED19(0x94, ObjectData.RETIRED19),
    RETIRED20(0x95, ObjectData.RETIRED20),

    ATTESTATION(0xf9, ObjectData.ATTESTATION);

    public final int value;
    public final byte[] object;

    Slot(int value, byte[] object) {
        this.value = value;
        this.object = object;
    }

    public static Slot fromValue(int value) {
        for (Slot type : Slot.values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Not a valid Slot :" + value);
    }
}

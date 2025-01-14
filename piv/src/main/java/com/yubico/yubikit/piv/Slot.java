/*
 * Copyright (C) 2019-2022 Yubico.
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
 * A PIV slot for storing a private key, with a corresponding object ID for storing a certificate.
 */
public enum Slot {
  AUTHENTICATION(0x9a, ObjectId.AUTHENTICATION),
  // CARD_MANAGEMENT (0x9b) is intentionally left out as it functions differently.
  SIGNATURE(0x9c, ObjectId.SIGNATURE),
  KEY_MANAGEMENT(0x9d, ObjectId.KEY_MANAGEMENT),
  CARD_AUTH(0x9e, ObjectId.CARD_AUTH),

  RETIRED1(0x82, ObjectId.RETIRED1),
  RETIRED2(0x83, ObjectId.RETIRED2),
  RETIRED3(0x84, ObjectId.RETIRED3),
  RETIRED4(0x85, ObjectId.RETIRED4),
  RETIRED5(0x86, ObjectId.RETIRED5),
  RETIRED6(0x87, ObjectId.RETIRED6),
  RETIRED7(0x88, ObjectId.RETIRED7),
  RETIRED8(0x89, ObjectId.RETIRED8),
  RETIRED9(0x8a, ObjectId.RETIRED9),
  RETIRED10(0x8b, ObjectId.RETIRED10),
  RETIRED11(0x8c, ObjectId.RETIRED11),
  RETIRED12(0x8d, ObjectId.RETIRED12),
  RETIRED13(0x8e, ObjectId.RETIRED13),
  RETIRED14(0x8f, ObjectId.RETIRED14),
  RETIRED15(0x90, ObjectId.RETIRED15),
  RETIRED16(0x91, ObjectId.RETIRED16),
  RETIRED17(0x92, ObjectId.RETIRED17),
  RETIRED18(0x93, ObjectId.RETIRED18),
  RETIRED19(0x94, ObjectId.RETIRED19),
  RETIRED20(0x95, ObjectId.RETIRED20),

  ATTESTATION(0xf9, ObjectId.ATTESTATION);

  public final int value;
  public final int objectId;

  Slot(int value, int objectId) {
    this.value = value;
    this.objectId = objectId;
  }

  /**
   * Gets the String alias for the slot, which is a HEX representation of the slot value.
   *
   * @return the slot alias
   */
  public String getStringAlias() {
    return Integer.toString(value, 16);
  }

  /** Returns the PIV slot corresponding to the given ID. */
  public static Slot fromValue(int value) {
    for (Slot type : Slot.values()) {
      if (type.value == value) {
        return type;
      }
    }
    throw new IllegalArgumentException("Not a valid Slot :" + value);
  }

  /**
   * Returns the PIV slot corresponding to the given String alias.
   *
   * <p>The alias should be the HEX representation of the slot value.
   *
   * @param alias a slot value as HEX string
   * @return a Slot
   */
  public static Slot fromStringAlias(String alias) {
    return fromValue(Integer.parseInt(alias, 16));
  }
}

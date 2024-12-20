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

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.util.Tlvs;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nullable;

public class ApplicationRelatedData {
  private static final int TAG_DISCRETIONARY = 0x73;
  private final OpenPgpAid aid;
  private final byte[] historical;
  @Nullable private final ExtendedLengthInfo extendedLengthInfo;
  @Nullable private final EnumSet<GeneralFeatureManagement> generalFeatureManagement;
  private final DiscretionaryDataObjects discretionary;

  public ApplicationRelatedData(
      OpenPgpAid aid,
      byte[] historical,
      @Nullable ExtendedLengthInfo extendedLengthInfo,
      @Nullable EnumSet<GeneralFeatureManagement> generalFeatureManagement,
      DiscretionaryDataObjects discretionary) {
    this.aid = aid;
    this.historical = historical;
    this.extendedLengthInfo = extendedLengthInfo;
    this.generalFeatureManagement = generalFeatureManagement;
    this.discretionary = discretionary;
  }

  public OpenPgpAid getAid() {
    return aid;
  }

  public byte[] getHistorical() {
    return Arrays.copyOf(historical, historical.length);
  }

  @Nullable
  public ExtendedLengthInfo getExtendedLengthInfo() {
    return extendedLengthInfo;
  }

  @Nullable
  public EnumSet<GeneralFeatureManagement> getGeneralFeatureManagement() {
    return generalFeatureManagement;
  }

  public DiscretionaryDataObjects getDiscretionary() {
    return discretionary;
  }

  static ApplicationRelatedData parse(byte[] encoded) {
    try {
      byte[] outer = Tlvs.unpackValue(Do.APPLICATION_RELATED_DATA, encoded);
      Map<Integer, byte[]> data = Tlvs.decodeMap(outer);
      EnumSet<GeneralFeatureManagement> generalFeatureManagement = null;
      if (data.containsKey(Do.GENERAL_FEATURE_MANAGEMENT)) {
        byte flags = Tlvs.unpackValue(0x81, data.get(Do.GENERAL_FEATURE_MANAGEMENT))[0];
        Set<GeneralFeatureManagement> flagSet = new HashSet<>();
        for (GeneralFeatureManagement flag : GeneralFeatureManagement.values()) {
          if ((flag.value & flags) != 0) {
            flagSet.add(flag);
          }
        }
        generalFeatureManagement = EnumSet.copyOf(flagSet);
      }
      byte[] discretionary = data.get(TAG_DISCRETIONARY);
      return new ApplicationRelatedData(
          new OpenPgpAid(data.get(Do.AID)),
          data.get(Do.HISTORICAL_BYTES),
          data.containsKey(Do.EXTENDED_LENGTH_INFO)
              ? ExtendedLengthInfo.parse(data.get(Do.EXTENDED_LENGTH_INFO))
              : null,
          generalFeatureManagement,
          DiscretionaryDataObjects.parse(
              // Older keys have data in outer dict
              discretionary.length > 0 ? discretionary : outer));
    } catch (BadResponseException e) {
      throw new IllegalArgumentException(e);
    }
  }
}

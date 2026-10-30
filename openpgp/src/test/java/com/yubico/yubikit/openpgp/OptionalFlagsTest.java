/*
 * Copyright (C) 2026 Yubico.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.EnumSet;
import org.junit.Test;

public class OptionalFlagsTest {
  @Test
  public void extendedCapabilitiesAllZeroIsEmptySet() {
    ExtendedCapabilities caps = ExtendedCapabilities.parse(new byte[10]);
    assertTrue(caps.getFlags().isEmpty());
  }

  @Test
  public void extendedCapabilitiesIndividualBits() {
    for (ExtendedCapabilityFlag flag : ExtendedCapabilityFlag.values()) {
      byte[] encoded = new byte[10];
      encoded[0] = flag.value;
      assertEquals(EnumSet.of(flag), ExtendedCapabilities.parse(encoded).getFlags());
    }
  }

  @Test
  public void extendedCapabilitiesMixedBits() {
    byte[] encoded = new byte[10];
    encoded[0] =
        (byte) (ExtendedCapabilityFlag.KDF.value | ExtendedCapabilityFlag.KEY_IMPORT.value);
    assertEquals(
        EnumSet.of(ExtendedCapabilityFlag.KDF, ExtendedCapabilityFlag.KEY_IMPORT),
        ExtendedCapabilities.parse(encoded).getFlags());
  }

  @Test
  public void applicationRelatedDataWithNoOptionalFlags() {
    ApplicationRelatedData data =
        ApplicationRelatedData.parse(
            OpenPgpSessionTest.mockApplicationRelatedData((byte) 0, (byte) 0));
    assertTrue(data.getDiscretionary().getExtendedCapabilities().getFlags().isEmpty());
    EnumSet<GeneralFeatureManagement> gfm = data.getGeneralFeatureManagement();
    assertNotNull(gfm);
    assertTrue(gfm.isEmpty());
  }

  @Test
  public void applicationRelatedDataGeneralFeatureBits() {
    for (GeneralFeatureManagement feature : GeneralFeatureManagement.values()) {
      ApplicationRelatedData data =
          ApplicationRelatedData.parse(
              OpenPgpSessionTest.mockApplicationRelatedData((byte) 1, feature.value));
      assertEquals(EnumSet.of(feature), data.getGeneralFeatureManagement());
    }
    ApplicationRelatedData mixed =
        ApplicationRelatedData.parse(
            OpenPgpSessionTest.mockApplicationRelatedData(
                (byte) 1,
                (byte)
                    (GeneralFeatureManagement.LED.value | GeneralFeatureManagement.BUTTON.value)));
    assertEquals(
        EnumSet.of(GeneralFeatureManagement.LED, GeneralFeatureManagement.BUTTON),
        mixed.getGeneralFeatureManagement());
  }

  @Test
  public void applicationRelatedDataWithoutGeneralFeatureManagement() {
    ApplicationRelatedData data =
        ApplicationRelatedData.parse(OpenPgpSessionTest.mockApplicationRelatedData());
    assertNull(data.getGeneralFeatureManagement());
    assertEquals(
        EnumSet.of(ExtendedCapabilityFlag.KDF),
        data.getDiscretionary().getExtendedCapabilities().getFlags());
  }
}

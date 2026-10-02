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

package com.yubico.yubikit.android.transport.usb.connection;

import com.yubico.yubikit.Codec;
import org.junit.Assert;
import org.junit.Test;

/** Walking the interface bytes of an ISO 7816-3 ATR (§8.2). */
public class AtrInterfaceBytesTest {

  /**
   * The ATR of the card behind the Identiv SCR3500 C. TS=3B, T0=FD (Y1=F, so TA1/TB1/TC1/TD1 are
   * all present, K=13), TA1=13, TB1=00, TC1=00, TD1=81 (Y2=8, so only TD2 follows; T=1), TD2=31
   * (Y3=3, so TA3/TB3 follow; T=1), TA3=FE, TB3=15, then 13 historical bytes and TCK.
   */
  private static final String SCR3500_ATR = "3bfd1300008131fe158073c021c057597562694b657940";

  @Test
  public void testParsesRealAtr() {
    AtrInterfaceBytes bytes = AtrInterfaceBytes.parse(Codec.fromHex(SCR3500_ATR));

    Assert.assertEquals(Byte.valueOf((byte) 0x13), bytes.ta(1));
    Assert.assertEquals(Byte.valueOf((byte) 0x00), bytes.tb(1));
    Assert.assertEquals(Byte.valueOf((byte) 0x00), bytes.tc(1));
    Assert.assertEquals(Byte.valueOf((byte) 0xFE), bytes.ta(3));
    Assert.assertEquals(Byte.valueOf((byte) 0x15), bytes.tb(3));
  }

  /** Level 2 announced nothing but TD2, so every level-2 byte is absent. */
  @Test
  public void testAbsentBytesAreNull() {
    AtrInterfaceBytes bytes = AtrInterfaceBytes.parse(Codec.fromHex(SCR3500_ATR));

    Assert.assertNull(bytes.ta(2));
    Assert.assertNull(bytes.tb(2));
    Assert.assertNull(bytes.tc(2));
    Assert.assertNull(bytes.tc(3));
    Assert.assertNull(bytes.ta(4));
  }

  /** T0=00 announces no interface bytes at all; the historical bytes that follow are not ours. */
  @Test
  public void testAtrWithNoInterfaceBytes() {
    AtrInterfaceBytes bytes = AtrInterfaceBytes.parse(Codec.fromHex("3B00"));

    Assert.assertNull(bytes.ta(1));
    Assert.assertNull(bytes.tb(1));
    Assert.assertNull(bytes.tc(1));
  }

  /** Y1=1 announces TA1 alone, and the byte after it belongs to the historical bytes. */
  @Test
  public void testAtrWithOnlyTa1() {
    AtrInterfaceBytes bytes = AtrInterfaceBytes.parse(Codec.fromHex("3B1196"));

    Assert.assertEquals(Byte.valueOf((byte) 0x96), bytes.ta(1));
    Assert.assertNull(bytes.tb(1));
    Assert.assertNull(bytes.ta(2));
  }

  /** Y1=4 announces TC1 without TA1 or TB1, so position, not order of arrival, decides. */
  @Test
  public void testAtrWithOnlyTc1() {
    AtrInterfaceBytes bytes = AtrInterfaceBytes.parse(Codec.fromHex("3B41FF"));

    Assert.assertNull(bytes.ta(1));
    Assert.assertNull(bytes.tb(1));
    Assert.assertEquals(Byte.valueOf((byte) 0xFF), bytes.tc(1));
  }

  /**
   * An ATR cut off mid-walk keeps whatever was read. Every interface byte is optional anyway, so a
   * partial parse degrades to defaults instead of failing the connection.
   */
  @Test
  public void testTruncatedAtrKeepsWhatItRead() {
    // T0=F0 announces TA1/TB1/TC1/TD1 but the ATR ends after TA1.
    AtrInterfaceBytes bytes = AtrInterfaceBytes.parse(Codec.fromHex("3BF011"));

    Assert.assertEquals(Byte.valueOf((byte) 0x11), bytes.ta(1));
    Assert.assertNull(bytes.tb(1));
  }

  /** A missing or unusably short ATR parses to all-absent rather than throwing. */
  @Test
  public void testDegenerateAtrs() {
    Assert.assertNull(AtrInterfaceBytes.parse(null).ta(1));
    Assert.assertNull(AtrInterfaceBytes.parse(new byte[0]).ta(1));
    Assert.assertNull(AtrInterfaceBytes.parse(Codec.fromHex("3B")).ta(1));
  }

  /** Levels past 4 carry nothing we act on, and asking for one is not an error. */
  @Test
  public void testLevelOutOfRange() {
    AtrInterfaceBytes bytes = AtrInterfaceBytes.parse(Codec.fromHex(SCR3500_ATR));

    Assert.assertNull(bytes.ta(0));
    Assert.assertNull(bytes.ta(5));
  }
}

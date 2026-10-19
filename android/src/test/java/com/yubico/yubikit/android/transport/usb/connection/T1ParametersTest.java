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

/** Building the CCID 1.10 §6.3.6 T=1 parameter structure out of a card's ATR. */
public class T1ParametersTest {

  /** The Identiv SCR3500 C card's ATR: TA1=13, TC1=00, TA3=FE, TB3=15. */
  private static final String SCR3500_ATR = "3bfd1300008131fe158073c021c057597562694b657940";

  /**
   * Fi/Di and IFSC come straight from the ATR; the fixed bytes are T=1 with LRC and direct
   * convention, clock-stop disallowed, and NAD 00.
   */
  @Test
  public void testFromRealAtr() {
    T1Parameters parameters = T1Parameters.fromAtr(Codec.fromHex(SCR3500_ATR));

    //         Fi/Di TCCK guard  WI  stop IFSC NAD
    Assert.assertArrayEquals(Codec.fromHex("1310001500FE00"), parameters.toBytes());
  }

  /** An ATR announcing nothing leaves every field at its ISO 7816-3 default. */
  @Test
  public void testDefaultsWhenAtrIsSilent() {
    T1Parameters parameters = T1Parameters.fromAtr(Codec.fromHex("3B00"));

    //         Fi/Di TCCK guard  WI  stop IFSC NAD
    Assert.assertArrayEquals(Codec.fromHex("1110004D002000"), parameters.toBytes());
  }

  /** No ATR at all is the same as an ATR that announced nothing. */
  @Test
  public void testDefaultsWhenAtrIsAbsent() {
    Assert.assertArrayEquals(Codec.fromHex("1110004D002000"), T1Parameters.fromAtr(null).toBytes());
  }

  /**
   * Each of the four consumed bytes lands in its own slot, so a card that sets only some of them
   * does not shift the others. TA1=96, TC1=FF, TA3=80, TB3=45.
   */
  @Test
  public void testEachInterfaceByteLandsInItsOwnSlot() {
    // TS=3B T0=D0 (Y1=D -> TA1/TC1/TD1) TA1=96 TC1=FF TD1=81 (Y2=8 -> TD2)
    // TD2=B1 (Y3=B -> TA3/TB3/TD3) TA3=80 TB3=45 TD3=00 (Y4=0).
    T1Parameters parameters = T1Parameters.fromAtr(Codec.fromHex("3BD096FF81B1804500"));

    //         Fi/Di TCCK guard  WI  stop IFSC NAD
    Assert.assertArrayEquals(Codec.fromHex("9610FF45008000"), parameters.toBytes());
  }

  /** The logging accessors report the bytes as unsigned, which is how the spec names them. */
  @Test
  public void testUnsignedAccessors() {
    T1Parameters parameters = T1Parameters.fromAtr(Codec.fromHex(SCR3500_ATR));

    Assert.assertEquals(0x13, parameters.findexDindex());
    Assert.assertEquals(0xFE, parameters.ifsc());
  }

  /**
   * The SCR3500 card announces BWI=1: 11 + 2 x 960 = 1931 etu. At the 4 MHz the test descriptor
   * gives and the default 372 clocks per etu that is 1931 x 372 / 4000 = 179.6 ms, rounded up.
   */
  @Test
  public void testBlockWaitingTimeFromAtr() {
    T1Parameters parameters = T1Parameters.fromAtr(Codec.fromHex(SCR3500_ATR));

    Assert.assertEquals(1, parameters.bwi());
    Assert.assertEquals(180, parameters.blockWaitingTimeMillis(4000));
  }

  /** An ATR that omits TB3 gets the default BWI of 4: 11 + 16 x 960 = 15371 etu. */
  @Test
  public void testBlockWaitingTimeOfDefaults() {
    T1Parameters parameters = T1Parameters.fromAtr(Codec.fromHex("3B00"));

    Assert.assertEquals(4, parameters.bwi());
    // 15371 x 372 / 4000 = 1429.5 ms
    Assert.assertEquals(1430, parameters.blockWaitingTimeMillis(4000));
  }

  /**
   * A card whose Fi is above the default can be running a longer etu than 372 clocks, so the bound
   * follows it: TA1=D1 is Fi=2048.
   */
  @Test
  public void testLargeFiLengthensTheBound() {
    // TS=3B T0=D0 (TA1/TC1/TD1) TA1=D1 TC1=FF TD1=81 TD2=B1 TA3=80 TB3=45 TD3=00
    T1Parameters parameters = T1Parameters.fromAtr(Codec.fromHex("3BD0D1FF81B1804500"));

    // 15371 x 2048 / 4000 = 7870 ms
    Assert.assertEquals(7870, parameters.blockWaitingTimeMillis(4000));
  }

  /**
   * A card asking for a faster rate does not shorten the bound: whether the reader got there is not
   * ours to know, and a bound that assumed it would fire early if it had not. TA1=96 is Fi=512,
   * Di=32; the bound uses Fi with Di=1.
   */
  @Test
  public void testFasterRateIsNotAssumed() {
    T1Parameters parameters = T1Parameters.fromAtr(Codec.fromHex("3BD096FF81B1804500"));

    // 15371 x 512 / 4000 = 1967.5 ms
    Assert.assertEquals(1968, parameters.blockWaitingTimeMillis(4000));
  }

  /** BWI above 9 is reserved, so a card that sends it is held to the largest defined value. */
  @Test
  public void testReservedBwiIsClamped() {
    Assert.assertEquals(
        T1Parameters.blockWaitingTimeMillis(9, 372, 4000),
        T1Parameters.blockWaitingTimeMillis(15, 372, 4000));
  }

  /** A reader that gives no clock leaves a 3.57 MHz assumption rather than a division by zero. */
  @Test
  public void testMissingClockFallsBack() {
    T1Parameters parameters = T1Parameters.fromAtr(Codec.fromHex("3B00"));

    // 15371 x 372 / 3571 = 1601.2 ms
    Assert.assertEquals(1602, parameters.blockWaitingTimeMillis(0));
    Assert.assertEquals(
        parameters.blockWaitingTimeMillis(0), parameters.blockWaitingTimeMillis(3571));
  }

  /**
   * TD2 announces T=15, so TA3=C7 is global data and the IFSC stays at its default of 32. TS=3B
   * T0=80 TD1=81 (T=1) TD2=1F (Y3=1, T=15) TA3=C7.
   */
  @Test
  public void testGlobalTa3IsNotTakenAsIfsc() {
    T1Parameters parameters = T1Parameters.fromAtr(Codec.fromHex("3B80811FC7D9"));

    //         Fi/Di TCCK guard  WI  stop IFSC NAD
    Assert.assertArrayEquals(Codec.fromHex("1110004D002000"), parameters.toBytes());
  }

  /** T=15 before T=1 is malformed, but the T=1 parameters are still found at the T=1 level. */
  @Test
  public void testT1ParametersAfterT15AreFound() {
    // TD2=9F (Y3=9: TA3, TD3; T=15) TA3=C7 TD3=31 (Y4=3: TA4, TB4; T=1) TA4=20 TB4=15
    T1Parameters parameters = T1Parameters.fromAtr(Codec.fromHex("3B80819FC7312015"));

    //         Fi/Di TCCK guard  WI  stop IFSC NAD
    Assert.assertArrayEquals(Codec.fromHex("1110001500200" + "0"), parameters.toBytes());
  }
}

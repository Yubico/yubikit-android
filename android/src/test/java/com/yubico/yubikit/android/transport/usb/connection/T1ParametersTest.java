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
}

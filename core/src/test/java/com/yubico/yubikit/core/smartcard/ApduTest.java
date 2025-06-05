/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.core.smartcard;

import org.junit.Assert;
import org.junit.Test;

public class ApduTest {
  @Test
  public void testMixedBytesAndInts() {
    byte cla = 0x7f;
    byte ins = (byte) 0xff;
    int p1 = 0x7f;
    int p2 = 0xff;
    Apdu apdu = new Apdu(cla, ins, p1, p2, null);

    Assert.assertEquals(cla, apdu.getCla());
    Assert.assertEquals(ins, apdu.getIns());
    Assert.assertEquals(cla, apdu.getP1());
    Assert.assertEquals(ins, apdu.getP2());
  }
}

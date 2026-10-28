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

package com.yubico.yubikit.core.smartcard;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.scp.ScpState;
import com.yubico.yubikit.core.smartcard.scp.SessionKeys;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

/** GPC Amd D (SCP03) v1.2 §6.2.5: success and warning responses carry an R-MAC, even when empty. */
public class ScpProcessorTest {
  private static final int INS_EXTERNAL_AUTHENTICATE = 0x82;
  private static final SecretKey KEY = new SecretKeySpec(new byte[16], "AES");

  @BeforeClass
  public static void setUp() {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static ScpProcessor processor(ApduProcessor delegate) {
    ScpState state = new ScpState(new SessionKeys(KEY, KEY, KEY, null), new byte[16]);
    return new ScpProcessor(delegate, new ShortApduFormatter(), state);
  }

  private static ApduProcessor reply(int sw) {
    return apdu -> new ApduResponse(new byte[] {(byte) (sw >> 8), (byte) sw});
  }

  @Test
  public void emptySuccessWithoutRmacIsRefused() {
    assertThrows(
        BadResponseException.class,
        () -> processor(reply(0x9000)).sendApdu(new Apdu(0, 0xCA, 0, 0, new byte[0]), false));
  }

  @Test
  public void emptyWarningWithoutRmacIsRefused() {
    for (int sw : new int[] {0x6282, 0x63C2}) {
      assertThrows(
          BadResponseException.class,
          () -> processor(reply(sw)).sendApdu(new Apdu(0, 0xCA, 0, 0, new byte[0]), false));
    }
  }

  /** An R-MAC is 8 bytes, so a shorter data field cannot be a protected response. */
  @Test
  public void dataFieldShorterThanRmacIsRefused() {
    for (int length = 1; length < 8; length++) {
      final byte[] data = new byte[length + 2];
      data[length] = (byte) 0x90;
      ApduProcessor card = apdu -> new ApduResponse(data);
      assertThrows(
          BadResponseException.class,
          () -> processor(card).sendApdu(new Apdu(0, 0xCA, 0, 0, new byte[0]), false));
    }
  }

  @Test
  public void emptyErrorIsReturnedAsIs() throws Exception {
    ApduResponse response =
        processor(reply(0x6984)).sendApdu(new Apdu(0, 0xCA, 0, 0, new byte[0]), false);
    assertEquals((short) 0x6984, response.getSw());
    assertEquals(0, response.getData().length);
  }

  @Test
  public void externalAuthenticateWithoutRmacIsAccepted() throws Exception {
    ApduResponse response =
        processor(reply(0x9000))
            .sendApdu(new Apdu(0x84, INS_EXTERNAL_AUTHENTICATE, 0x33, 0, new byte[8]), false);
    assertEquals(SW.OK, response.getSw());
  }

  @Test
  public void emptySuccessWithValidRmacIsAccepted() throws Exception {
    ApduProcessor card =
        apdu -> {
          // Recompute the MAC chain the way the card does, then sign an empty 9000 with it.
          byte[] macedData = apdu.getData();
          byte[] apduData =
              new ShortApduFormatter()
                  .formatApdu(
                      (byte) apdu.getCla(),
                      apdu.getIns(),
                      apdu.getP1(),
                      apdu.getP2(),
                      macedData,
                      0,
                      macedData.length,
                      0);
          byte[] chain = cmac(new byte[16], Arrays.copyOf(apduData, apduData.length - 8));
          byte[] rmac = Arrays.copyOf(cmac(chain, new byte[] {(byte) 0x90, 0x00}), 8);
          return new ApduResponse(ByteBuffer.allocate(10).put(rmac).putShort(SW.OK).array());
        };

    ApduResponse response = processor(card).sendApdu(new Apdu(0, 0xCA, 0, 0, new byte[0]), false);

    assertEquals(SW.OK, response.getSw());
    assertArrayEquals(new byte[0], response.getData());
  }

  private static byte[] cmac(byte[] chain, byte[] data) {
    try {
      Mac mac = Mac.getInstance("AESCMAC");
      mac.init(KEY);
      mac.update(chain);
      return mac.doFinal(data);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}

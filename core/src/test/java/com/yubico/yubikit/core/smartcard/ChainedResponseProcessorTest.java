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
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.application.BadResponseException;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

public class ChainedResponseProcessorTest {
  private static final byte INS_SEND_REMAINING = (byte) 0xc0;
  private static final int MORE_DATA = 0x6100;
  private static final int OK = 0x9000;
  private static final int PIECE = 256;
  private static final int LIMIT = ChainedResponseProcessor.MAX_RESPONSE_LENGTH;
  private static final int MAX_EMPTY = ChainedResponseProcessor.MAX_EMPTY_ROUNDS;

  private static ApduResponse piece(int dataLength, int sw) {
    byte[] bytes = new byte[dataLength + 2];
    for (int i = 0; i < dataLength; i++) {
      bytes[i] = (byte) (i + 1);
    }
    bytes[dataLength] = (byte) (sw >> 8);
    bytes[dataLength + 1] = (byte) sw;
    return new ApduResponse(bytes);
  }

  private static ApduResponse piece(byte[] data, int sw) {
    byte[] bytes = Arrays.copyOf(data, data.length + 2);
    bytes[data.length] = (byte) (sw >> 8);
    bytes[data.length + 1] = (byte) sw;
    return new ApduResponse(bytes);
  }

  /** The card answers the command, and then each request for the rest, from the given pieces. */
  private static ChainedResponseProcessor card(ApduResponse... pieces) {
    final Deque<ApduResponse> script = new ArrayDeque<>(Arrays.asList(pieces));
    return new ChainedResponseProcessor(
        apdu -> {
          if (script.isEmpty()) {
            throw new IOException("Card was asked for more pieces than the script provides");
          }
          return script.remove();
        },
        INS_SEND_REMAINING);
  }

  private static Apdu command() {
    return new Apdu(0, 0xa1, 0, 0, null);
  }

  @Test
  public void responseWithoutChainingIsReturned() throws Exception {
    ApduResponse response = card(piece(new byte[] {0x0a}, OK)).sendApdu(command());

    assertArrayEquals(new byte[] {0x0a}, response.getData());
    assertEquals(OK, response.getSw() & 0xffff);
  }

  @Test
  public void chainedPiecesAreConcatenated() throws Exception {
    ApduResponse response =
        card(piece(new byte[] {0x0a}, MORE_DATA | 1), piece(new byte[] {0x0b}, OK))
            .sendApdu(command());

    assertArrayEquals(new byte[] {0x0a, 0x0b}, response.getData());
    assertEquals(OK, response.getSw() & 0xffff);
  }

  /** A card that only announces how much it will send answers the command without any data. */
  @Test
  public void anAnnouncementWithoutDataIsNormal() throws Exception {
    ApduResponse response =
        card(piece(0, MORE_DATA | 2), piece(new byte[] {0x0a, 0x0b}, OK)).sendApdu(command());

    assertArrayEquals(new byte[] {0x0a, 0x0b}, response.getData());
  }

  @Test
  public void emptyPiecesUpToTheLimitAreAccepted() throws Exception {
    ApduResponse[] pieces = new ApduResponse[MAX_EMPTY + 1];
    Arrays.fill(pieces, piece(0, MORE_DATA | 1));
    pieces[MAX_EMPTY] = piece(new byte[] {0x0a}, OK);

    ApduResponse response = card(pieces).sendApdu(command());

    assertArrayEquals(new byte[] {0x0a}, response.getData());
  }

  @Test
  public void oneEmptyPieceOverTheLimitIsRejected() {
    ApduResponse[] pieces = new ApduResponse[MAX_EMPTY + 2];
    Arrays.fill(pieces, piece(0, MORE_DATA | 1));
    pieces[MAX_EMPTY + 1] = piece(new byte[] {0x0a}, OK);

    BadResponseException e =
        assertThrows(BadResponseException.class, () -> card(pieces).sendApdu(command()));

    assertEquals("Response chain made no progress within 16 pieces", e.getMessage());
  }

  /** A piece that carries data starts the count again, so empty pieces spread out are fine. */
  @Test
  public void aPieceWithDataStartsTheEmptyCountAgain() throws Exception {
    ApduResponse[] pieces = new ApduResponse[61];
    for (int i = 0; i < pieces.length; i++) {
      boolean data = i % 11 == 10;
      pieces[i] = data ? piece(1, MORE_DATA | 1) : piece(0, MORE_DATA | 1);
    }
    pieces[60] = piece(1, OK);

    ApduResponse response = card(pieces).sendApdu(command());

    assertEquals(6, response.getData().length); // pieces 10, 21, 32, 43, 54 and the last
  }

  @Test
  public void aCardThatNeverDeliversDataIsRejected() {
    final AtomicInteger requests = new AtomicInteger();
    ChainedResponseProcessor processor =
        new ChainedResponseProcessor(
            apdu -> {
              requests.incrementAndGet();
              return piece(0, MORE_DATA | 0xf0);
            },
            INS_SEND_REMAINING);

    assertThrows(BadResponseException.class, () -> processor.sendApdu(command()));

    // The command and one request per piece, and not one more than the limit allows
    assertTrue(requests.get() <= MAX_EMPTY + 1);
  }

  /** The limit is on the data collected, and a response of exactly that size is accepted. */
  @Test
  public void aResponseOfExactlyTheLimitIsAccepted() throws Exception {
    int pieces = LIMIT / PIECE;
    ApduResponse[] script = new ApduResponse[pieces];
    for (int i = 0; i < pieces; i++) {
      script[i] = piece(PIECE, i == pieces - 1 ? OK : MORE_DATA);
    }

    ApduResponse response = card(script).sendApdu(command());

    assertEquals(LIMIT, response.getData().length);
  }

  @Test
  public void oneByteOverTheLimitIsRejected() {
    int pieces = LIMIT / PIECE + 1;
    ApduResponse[] script = new ApduResponse[pieces];
    for (int i = 0; i < pieces; i++) {
      script[i] = piece(i == pieces - 1 ? 1 : PIECE, i == pieces - 1 ? OK : MORE_DATA);
    }

    BadResponseException e =
        assertThrows(BadResponseException.class, () -> card(script).sendApdu(command()));

    assertEquals("Response chain exceeds " + LIMIT + " bytes", e.getMessage());
  }

  /** A card that keeps delivering data without ever ending the chain is stopped at the limit. */
  @Test
  public void aCardThatNeverEndsTheChainIsRejected() {
    final AtomicInteger requests = new AtomicInteger();
    ChainedResponseProcessor processor =
        new ChainedResponseProcessor(
            apdu -> {
              requests.incrementAndGet();
              return piece(PIECE, MORE_DATA);
            },
            INS_SEND_REMAINING);

    assertThrows(BadResponseException.class, () -> processor.sendApdu(command()));

    assertTrue(requests.get() <= LIMIT / PIECE + 1);
  }
}

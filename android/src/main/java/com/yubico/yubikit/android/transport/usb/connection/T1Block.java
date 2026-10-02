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

import java.io.IOException;
import java.util.Arrays;
import java.util.Locale;

/**
 * A single ISO 7816-3 T=1 block: the three-byte prologue (NAD, PCB, LEN), up to {@link
 * #MAX_INF_LENGTH} information bytes, and a one-byte LRC epilogue (§11.3).
 *
 * <p>Only the LRC form of the epilogue is implemented. CRC is legal per §11.3.4 but is announced in
 * TC3 of the ATR, which no card we talk to sets.
 */
final class T1Block {

  /** NAD for a host-to-card exchange with no node addressing (§11.3.2.1). */
  static final byte NAD_DEFAULT = (byte) 0x00;

  /**
   * Largest INF a single block can carry: LEN is one byte and 0xFF is reserved for future use
   * (§11.3.2.3), so 254 is the ceiling regardless of the negotiated IFSC.
   */
  static final int MAX_INF_LENGTH = 254;

  /** NAD + PCB + LEN + one LRC byte: the shortest legal block. */
  static final int MIN_BLOCK_LENGTH = 4;

  // PCB bit layout, ISO 7816-3 §11.3.2.2. An I-block has bit 8 clear;
  // an R-block has bits 8-7 = 10; an S-block has bits 8-7 = 11.
  private static final int PCB_TYPE_MASK = 0xC0;
  private static final int PCB_I_BLOCK_MASK = 0x80;
  private static final int PCB_R_BLOCK = 0x80;
  private static final int PCB_S_BLOCK = 0xC0;

  /** I-block bit 7: N(S), the send-sequence number of this block. */
  private static final int PCB_I_SEQUENCE_SHIFT = 6;

  /** I-block bit 6: the M-bit, "more blocks of this chain follow". */
  private static final int PCB_I_MORE = 0x20;

  /** R-block bit 5: N(R), the sequence number of the block expected next. */
  private static final int PCB_R_SEQUENCE_SHIFT = 4;

  /** R-block bits 2-1: why the block is being sent, 0 meaning "no error". */
  private static final int PCB_R_ERROR_MASK = 0x03;

  /** S-block bit 6: clear on a request from the other side, set on a response. */
  private static final int PCB_S_RESPONSE = 0x20;

  /** S-block bits 5-1: which control exchange this is. */
  private static final int PCB_S_CONTROL_MASK = 0x1F;

  /** S(IFS request/response): renegotiate the information field size (§11.6.2.3). */
  static final int S_CONTROL_IFS = 0x01;

  /** S(WTX request/response): the card asks for more block waiting time (§11.6.2.3). */
  static final int S_CONTROL_WTX = 0x03;

  final byte nad;
  final byte pcb;
  final byte[] inf;

  private T1Block(byte nad, byte pcb, byte[] inf) {
    this.nad = nad;
    this.pcb = pcb;
    this.inf = inf;
  }

  /** True when this block carries application data rather than a control exchange. */
  boolean isIBlock() {
    return (pcb & PCB_I_BLOCK_MASK) == 0;
  }

  boolean isRBlock() {
    return (pcb & PCB_TYPE_MASK) == PCB_R_BLOCK;
  }

  boolean isSBlock() {
    return (pcb & PCB_TYPE_MASK) == PCB_S_BLOCK;
  }

  /** N(S) of an I-block. Only meaningful when {@link #isIBlock()}. */
  int sequenceNumber() {
    return (pcb >> PCB_I_SEQUENCE_SHIFT) & 0x01;
  }

  /** The M-bit of an I-block: further blocks of this chain follow. */
  boolean moreFollows() {
    return (pcb & PCB_I_MORE) != 0;
  }

  /** N(R) of an R-block: the sequence number its sender expects to receive next. */
  int expectedSequenceNumber() {
    return (pcb >> PCB_R_SEQUENCE_SHIFT) & 0x01;
  }

  /** The error field of an R-block, 0 when the acknowledged block arrived intact (§11.6.2.2). */
  int rBlockError() {
    return pcb & PCB_R_ERROR_MASK;
  }

  /** True when an S-block is a request from the card rather than a response to one of ours. */
  boolean isSBlockRequest() {
    return (pcb & PCB_S_RESPONSE) == 0;
  }

  /** The control field of an S-block: {@link #S_CONTROL_IFS} or {@link #S_CONTROL_WTX}. */
  int sBlockControl() {
    return pcb & PCB_S_CONTROL_MASK;
  }

  /** The PCB of the S-block response that answers this S-block request, same control field. */
  byte sBlockResponsePcb() {
    return (byte) (pcb | PCB_S_RESPONSE);
  }

  /** Serialize this block, appending a freshly computed LRC. */
  byte[] toBytes() {
    byte[] block = new byte[3 + inf.length + 1];
    block[0] = nad;
    block[1] = pcb;
    block[2] = (byte) inf.length;
    System.arraycopy(inf, 0, block, 3, inf.length);
    block[3 + inf.length] = lrc(block, 3 + inf.length);
    return block;
  }

  /**
   * An I-block carrying {@code inf} with the given N(S). Set {@code moreFollows} on every block of
   * a chain but its last, so the receiver knows to keep acknowledging.
   */
  static T1Block iBlock(int sequenceNumber, byte[] inf, boolean moreFollows) {
    byte pcb = (byte) ((sequenceNumber & 0x01) << PCB_I_SEQUENCE_SHIFT);
    if (moreFollows) {
      pcb |= (byte) PCB_I_MORE;
    }
    return new T1Block(NAD_DEFAULT, pcb, inf);
  }

  /**
   * An R-block acknowledging receipt and asking for the block numbered {@code expectedSequence}
   * next. The two low bits stay clear, which is "no error" (§11.6.2.2).
   */
  static T1Block rBlock(int expectedSequence) {
    byte pcb = (byte) (PCB_R_BLOCK | ((expectedSequence & 0x01) << PCB_R_SEQUENCE_SHIFT));
    return new T1Block(NAD_DEFAULT, pcb, new byte[0]);
  }

  /** An S-block with an explicit PCB, used to echo a card's request back as a response. */
  static T1Block sBlock(byte pcb, byte[] inf) {
    return new T1Block(NAD_DEFAULT, pcb, inf);
  }

  /**
   * Parse a received block, verifying its length against LEN and its LRC.
   *
   * @throws IOException if the block is truncated, claims more INF than it carries, or fails the
   *     LRC check - all of which mean the exchange has lost framing and cannot be continued
   */
  static T1Block parse(byte[] bytes) throws IOException {
    if (bytes.length < MIN_BLOCK_LENGTH) {
      throw new IOException("Truncated T=1 block (" + bytes.length + " bytes)");
    }
    int len = bytes[2] & 0xFF;
    if (bytes.length < 3 + len + 1) {
      throw new IOException(
          "T=1 block claims LEN="
              + len
              + " but only "
              + (bytes.length - MIN_BLOCK_LENGTH)
              + " INF bytes available");
    }
    byte expected = lrc(bytes, 3 + len);
    byte actual = bytes[3 + len];
    if (expected != actual) {
      throw new IOException(
          "T=1 LRC mismatch: got 0x"
              + String.format(Locale.ROOT, "%02X", actual)
              + " expected 0x"
              + String.format(Locale.ROOT, "%02X", expected));
    }
    return new T1Block(bytes[0], bytes[1], Arrays.copyOfRange(bytes, 3, 3 + len));
  }

  /** XOR of the first {@code length} bytes: the LRC form of the epilogue (§11.3.4). */
  private static byte lrc(byte[] bytes, int length) {
    byte lrc = 0;
    for (int i = 0; i < length; i++) {
      lrc ^= bytes[i];
    }
    return lrc;
  }
}

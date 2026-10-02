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
import java.io.IOException;
import org.junit.Assert;
import org.junit.Test;

/** ISO 7816-3 §11.3 block framing: prologue, INF, LRC epilogue. */
public class T1BlockTest {

  /**
   * A single-block SELECT command. LRC is the XOR of everything before it: 00 ^ 00 ^ 0F ^ (00 ^ A4
   * ^ 04 ^ 00 ^ 09 ^ A0 ^ 00 ^ 00 ^ 03 ^ 08 ^ 00 ^ 00 ^ 10 ^ 00 ^ 00) = 0x1D.
   */
  @Test
  public void testIBlockSequenceZero() {
    byte[] inf = Codec.fromHex("00A4040009A0000003080000100000");
    Assert.assertArrayEquals(
        Codec.fromHex("00000F00A4040009A00000030800001000001D"),
        T1Block.iBlock(0, inf, false).toBytes());
  }

  /** N(S)=1 sets PCB bit 7, which also flips the LRC by the same 0x40. */
  @Test
  public void testIBlockSequenceOne() {
    byte[] inf = Codec.fromHex("00A4040009A0000003080000100000");
    Assert.assertArrayEquals(
        Codec.fromHex("00400F00A4040009A00000030800001000005D"),
        T1Block.iBlock(1, inf, false).toBytes());
  }

  /** The M-bit marks every block of an outbound chain but its last: PCB 0x00 becomes 0x20. */
  @Test
  public void testIBlockWithMoreBit() {
    Assert.assertArrayEquals(
        Codec.fromHex("002002AABB33"), T1Block.iBlock(0, Codec.fromHex("AABB"), true).toBytes());
    Assert.assertArrayEquals(
        Codec.fromHex("006002AABB73"), T1Block.iBlock(1, Codec.fromHex("AABB"), true).toBytes());
  }

  /** N(R) and the error field of an R-block sit in different bits from an I-block's N(S). */
  @Test
  public void testRBlockFields() throws IOException {
    Assert.assertEquals(1, T1Block.parse(Codec.fromHex("00900090")).expectedSequenceNumber());
    Assert.assertEquals(0, T1Block.parse(Codec.fromHex("00800080")).expectedSequenceNumber());
    Assert.assertEquals(0, T1Block.parse(Codec.fromHex("00900090")).rBlockError());
    // PCB=0x81: N(R)=0 with "EDC or parity error", a retransmission request.
    Assert.assertEquals(1, T1Block.parse(Codec.fromHex("00810081")).rBlockError());
  }

  /** An I-block with no INF still carries LEN=00 and an LRC. */
  @Test
  public void testIBlockEmptyInf() {
    Assert.assertArrayEquals(
        Codec.fromHex("00000000"), T1Block.iBlock(0, new byte[0], false).toBytes());
  }

  /** R-block acknowledging and asking for N(R)=1 next: PCB bit 8 set, bit 5 set. */
  @Test
  public void testRBlock() {
    Assert.assertArrayEquals(Codec.fromHex("00900090"), T1Block.rBlock(1).toBytes());
    Assert.assertArrayEquals(Codec.fromHex("00800080"), T1Block.rBlock(0).toBytes());
  }

  /** S-block with an explicit PCB, used to echo a card's request back as a response. */
  @Test
  public void testSBlock() {
    Assert.assertArrayEquals(
        Codec.fromHex("00E30101E3"), T1Block.sBlock((byte) 0xE3, Codec.fromHex("01")).toBytes());
  }

  @Test
  public void testParseIBlock() throws IOException {
    T1Block block = T1Block.parse(Codec.fromHex("000002900092"));

    Assert.assertTrue(block.isIBlock());
    Assert.assertFalse(block.isRBlock());
    Assert.assertFalse(block.isSBlock());
    Assert.assertFalse(block.moreFollows());
    Assert.assertEquals(0, block.sequenceNumber());
    Assert.assertArrayEquals(Codec.fromHex("9000"), block.inf);
  }

  /** PCB=0x20 is an I-block with N(S)=0 and the M-bit set: more blocks of this chain follow. */
  @Test
  public void testParseIBlockWithMoreBit() throws IOException {
    T1Block block = T1Block.parse(Codec.fromHex("002002AABB33"));

    Assert.assertTrue(block.isIBlock());
    Assert.assertTrue(block.moreFollows());
    Assert.assertEquals(0, block.sequenceNumber());
    Assert.assertArrayEquals(Codec.fromHex("AABB"), block.inf);
  }

  /** PCB=0x40 is an I-block with N(S)=1, the second block of a chain. */
  @Test
  public void testParseIBlockSequenceOne() throws IOException {
    T1Block block = T1Block.parse(Codec.fromHex("0040029000D2"));

    Assert.assertTrue(block.isIBlock());
    Assert.assertEquals(1, block.sequenceNumber());
  }

  @Test
  public void testParseRBlock() throws IOException {
    T1Block block = T1Block.parse(Codec.fromHex("00900090"));

    Assert.assertTrue(block.isRBlock());
    Assert.assertFalse(block.isIBlock());
    Assert.assertFalse(block.isSBlock());
    Assert.assertEquals(0, block.inf.length);
  }

  /** PCB=0xC3 is a WTX request from the card; its response echoes it with bit 6 set. */
  @Test
  public void testParseSBlockWtxRequest() throws IOException {
    T1Block block = T1Block.parse(Codec.fromHex("00C30101C3"));

    Assert.assertTrue(block.isSBlock());
    Assert.assertTrue(block.isSBlockRequest());
    Assert.assertEquals(T1Block.S_CONTROL_WTX, block.sBlockControl());
    Assert.assertEquals((byte) 0xE3, block.sBlockResponsePcb());
  }

  /** PCB=0xC1 is an IFS request, carrying the proposed IFSC in INF. */
  @Test
  public void testParseSBlockIfsRequest() throws IOException {
    T1Block block = T1Block.parse(Codec.fromHex("00C101FE3E"));

    Assert.assertTrue(block.isSBlock());
    Assert.assertTrue(block.isSBlockRequest());
    Assert.assertEquals(T1Block.S_CONTROL_IFS, block.sBlockControl());
    Assert.assertEquals((byte) 0xE1, block.sBlockResponsePcb());
    Assert.assertArrayEquals(Codec.fromHex("FE"), block.inf);
  }

  /** Bit 6 set means the block is a response to our request, not a fresh request. */
  @Test
  public void testParseSBlockResponse() throws IOException {
    T1Block block = T1Block.parse(Codec.fromHex("00E30101E3"));

    Assert.assertTrue(block.isSBlock());
    Assert.assertFalse(block.isSBlockRequest());
  }

  /** Anything shorter than NAD+PCB+LEN+LRC cannot be a block at all. */
  @Test
  public void testParseRejectsTruncatedBlock() {
    try {
      T1Block.parse(Codec.fromHex("0000"));
      Assert.fail("Expected IOException for a block below the 4-byte minimum");
    } catch (IOException e) {
      Assert.assertEquals("Truncated T=1 block (2 bytes)", e.getMessage());
    }
  }

  /** LEN promising more INF than the block carries means framing was lost upstream. */
  @Test
  public void testParseRejectsLenBeyondBuffer() {
    try {
      T1Block.parse(Codec.fromHex("00000A9000"));
      Assert.fail("Expected IOException for LEN past the end of the block");
    } catch (IOException e) {
      Assert.assertEquals("T=1 block claims LEN=10 but only 1 INF bytes available", e.getMessage());
    }
  }

  /** A corrupted block has to be rejected rather than passed up as a response APDU. */
  @Test
  public void testParseRejectsLrcMismatch() {
    try {
      T1Block.parse(Codec.fromHex("0000029000FF"));
      Assert.fail("Expected IOException for LRC mismatch");
    } catch (IOException e) {
      Assert.assertEquals("T=1 LRC mismatch: got 0xFF expected 0x92", e.getMessage());
    }
  }

  /** Bytes past the LRC (USB packet padding) are ignored: LEN, not the buffer, delimits INF. */
  @Test
  public void testParseIgnoresTrailingBytes() throws IOException {
    T1Block block = T1Block.parse(Codec.fromHex("00000290009200000000"));

    Assert.assertArrayEquals(Codec.fromHex("9000"), block.inf);
  }

  /** Round-trip at the 254-byte ceiling, the largest INF a one-byte LEN can address. */
  @Test
  public void testMaxLengthRoundTrip() throws IOException {
    byte[] inf = new byte[T1Block.MAX_INF_LENGTH];
    for (int i = 0; i < inf.length; i++) {
      inf[i] = (byte) i;
    }

    T1Block parsed = T1Block.parse(T1Block.iBlock(0, inf, false).toBytes());

    Assert.assertArrayEquals(inf, parsed.inf);
  }
}

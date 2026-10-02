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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import org.junit.Assert;
import org.junit.Test;

/**
 * The T=1 exchange on top of a scripted card, with the CCID transport stubbed out. What goes over
 * USB is {@link UsbSmartCardConnectionTest}'s business; here only the block conversation matters.
 */
public class T1ProtocolTest {

  /** The IFSC the cards behind these readers announce in TA3, and the block ceiling besides. */
  private static final int IFSC_254 = 254;

  /** A SELECT whose single-block encoding is asserted throughout. */
  private static final String SELECT_APDU = "00A4040009A0000003080000100000";

  private static final String SELECT_I_BLOCK_NS0 = "00000F00A4040009A00000030800001000001D";
  private static final String SELECT_I_BLOCK_NS1 = "00400F00A4040009A00000030800001000005D";

  /** Card I-block { PCB=00 (N(S)=0, M=0) LEN=02 INF=9000 LRC=92 }. */
  private static final String OK_I_BLOCK = "000002900092";

  /** Replays a fixed list of card answers and records what was sent to get them. */
  private static final class ScriptedCard implements T1Protocol.BlockTransport {
    private final Deque<byte[]> answers = new ArrayDeque<>();
    private final List<byte[]> sent = new ArrayList<>();

    ScriptedCard(String... answerHex) {
      for (String hex : answerHex) {
        answers.add(Codec.fromHex(hex));
      }
    }

    @Override
    public byte[] exchange(byte[] block) throws IOException {
      sent.add(block);
      if (answers.isEmpty()) {
        throw new IOException("Card was asked for more blocks than the script provides");
      }
      return answers.remove();
    }

    void assertSent(String... expectedHex) {
      Assert.assertEquals("Wrong number of blocks sent", expectedHex.length, sent.size());
      for (int i = 0; i < expectedHex.length; i++) {
        Assert.assertArrayEquals(
            "Block " + i + " differs", Codec.fromHex(expectedHex[i]), sent.get(i));
      }
    }
  }

  /** An APDU of {@code length} bytes, distinguishable byte by byte once it is reassembled. */
  private static byte[] counting(int length) {
    byte[] apdu = new byte[length];
    for (int i = 0; i < length; i++) {
      apdu[i] = (byte) i;
    }
    return apdu;
  }

  /** The INF fields of the given blocks concatenated, to check a chain against what was chained. */
  private static byte[] infOf(byte[]... blocks) throws IOException {
    ByteArrayOutputStream joined = new ByteArrayOutputStream();
    for (byte[] block : blocks) {
      byte[] inf = T1Block.parse(block).inf;
      joined.write(inf, 0, inf.length);
    }
    return joined.toByteArray();
  }

  /** The common case: one command I-block, one answering I-block with the M-bit clear. */
  @Test
  public void testSingleBlockExchange() throws IOException {
    ScriptedCard card = new ScriptedCard(OK_I_BLOCK);

    byte[] response = new T1Protocol(card, IFSC_254).sendApdu(Codec.fromHex(SELECT_APDU));

    card.assertSent(SELECT_I_BLOCK_NS0);
    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /**
   * A chained response: the card's first I-block sets the M-bit, we acknowledge with an R-block
   * naming the sequence number we expect next, and the INF of both blocks concatenates into the
   * response APDU.
   */
  @Test
  public void testChainedResponseIsReassembled() throws IOException {
    ScriptedCard card =
        new ScriptedCard(
            // PCB=20: N(S)=0, M=1, INF=AABB
            "002002AABB33",
            // PCB=40: N(S)=1, M=0, INF=9000
            "0040029000D2");

    byte[] response = new T1Protocol(card, IFSC_254).sendApdu(Codec.fromHex(SELECT_APDU));

    // R-block PCB=90: N(R)=1, no error.
    card.assertSent(SELECT_I_BLOCK_NS0, "00900090");
    Assert.assertArrayEquals(Codec.fromHex("AABB9000"), response);
  }

  /** Three inbound blocks exercise the R-block's N(R) toggling back to 0. */
  @Test
  public void testChainedResponseThreeBlocks() throws IOException {
    ScriptedCard card =
        new ScriptedCard(
            "002001AA8B", // N(S)=0, M=1, INF=AA
            "006001BBDA", // N(S)=1, M=1, INF=BB
            "000002900092"); // N(S)=0, M=0, INF=9000

    byte[] response = new T1Protocol(card, IFSC_254).sendApdu(Codec.fromHex(SELECT_APDU));

    card.assertSent(SELECT_I_BLOCK_NS0, "00900090", "00800080");
    Assert.assertArrayEquals(Codec.fromHex("AABB9000"), response);
  }

  /**
   * A waiting-time extension request is granted by echoing it back with the response bit set; the
   * card then answers normally.
   */
  @Test
  public void testWtxRequestIsGranted() throws IOException {
    // PCB=C3: S-block request, control=WTX, INF=01 (multiplier).
    ScriptedCard card = new ScriptedCard("00C30101C3", OK_I_BLOCK);

    byte[] response = new T1Protocol(card, IFSC_254).sendApdu(Codec.fromHex(SELECT_APDU));

    // PCB=E3: same control, response bit set, INF echoed.
    card.assertSent(SELECT_I_BLOCK_NS0, "00E30101E3");
    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /** An IFS renegotiation is answered the same way, agreeing to the size the card proposed. */
  @Test
  public void testIfsRequestIsAcknowledged() throws IOException {
    // PCB=C1: S-block request, control=IFS, INF=FE (IFSC 254).
    ScriptedCard card = new ScriptedCard("00C101FE3E", OK_I_BLOCK);

    byte[] response = new T1Protocol(card, IFSC_254).sendApdu(Codec.fromHex(SELECT_APDU));

    card.assertSent(SELECT_I_BLOCK_NS0, "00E101FE1E");
    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /** N(S) advances once per completed exchange, not once per block (§11.6.2.2). */
  @Test
  public void testSequenceNumberTogglesBetweenExchanges() throws IOException {
    ScriptedCard card = new ScriptedCard(OK_I_BLOCK, OK_I_BLOCK, OK_I_BLOCK);
    T1Protocol protocol = new T1Protocol(card, IFSC_254);

    protocol.sendApdu(Codec.fromHex(SELECT_APDU));
    protocol.sendApdu(Codec.fromHex(SELECT_APDU));
    protocol.sendApdu(Codec.fromHex(SELECT_APDU));

    card.assertSent(SELECT_I_BLOCK_NS0, SELECT_I_BLOCK_NS1, SELECT_I_BLOCK_NS0);
  }

  /** A chained response does not advance N(S) any further than an unchained one. */
  @Test
  public void testSequenceNumberTogglesOncePerChainedExchange() throws IOException {
    ScriptedCard card = new ScriptedCard("002002AABB33", "0040029000D2", OK_I_BLOCK);
    T1Protocol protocol = new T1Protocol(card, IFSC_254);

    protocol.sendApdu(Codec.fromHex(SELECT_APDU));
    protocol.sendApdu(Codec.fromHex(SELECT_APDU));

    card.assertSent(SELECT_I_BLOCK_NS0, "00900090", SELECT_I_BLOCK_NS1);
  }

  /** 254 INF bytes is the ceiling, and it has to be reachable rather than off by one. */
  @Test
  public void testMaximumSizedApduIsAccepted() throws IOException {
    ScriptedCard card = new ScriptedCard(OK_I_BLOCK);

    byte[] response = new T1Protocol(card, IFSC_254).sendApdu(new byte[T1Block.MAX_INF_LENGTH]);

    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /**
   * A command past the block ceiling goes out as a chain. This is the case that made outbound
   * chaining necessary: a short APDU with Lc = 255 is 261 bytes, and refusing it would leave a TPDU
   * reader unable to carry a write the card is perfectly willing to accept.
   */
  @Test
  public void testCommandIsChainedWhenItExceedsIfsc() throws IOException {
    // R-block PCB=90 acknowledging the first chunk and asking for N(S)=1.
    ScriptedCard card = new ScriptedCard("00900090", OK_I_BLOCK);
    byte[] apdu = counting(261);

    byte[] response = new T1Protocol(card, IFSC_254).sendApdu(apdu);

    Assert.assertEquals(2, card.sent.size());
    // First chunk: N(S)=0 with the M-bit set, a full 254 INF bytes.
    Assert.assertEquals((byte) 0x20, card.sent.get(0)[1]);
    Assert.assertEquals((byte) 254, card.sent.get(0)[2]);
    // Last chunk: N(S)=1, M clear, the remaining 7 bytes.
    Assert.assertEquals((byte) 0x40, card.sent.get(1)[1]);
    Assert.assertEquals((byte) 7, card.sent.get(1)[2]);
    Assert.assertArrayEquals(apdu, infOf(card.sent.get(0), card.sent.get(1)));
    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /** A card that announced a small IFSC gets chunks that size, not the 254-byte maximum. */
  @Test
  public void testCommandIsChunkedAtTheAnnouncedIfsc() throws IOException {
    ScriptedCard card = new ScriptedCard("00900090", "00800080", OK_I_BLOCK);
    byte[] apdu = counting(70);

    new T1Protocol(card, 32).sendApdu(apdu);

    Assert.assertEquals(3, card.sent.size());
    Assert.assertEquals((byte) 32, card.sent.get(0)[2]);
    Assert.assertEquals((byte) 32, card.sent.get(1)[2]);
    Assert.assertEquals((byte) 6, card.sent.get(2)[2]);
    Assert.assertArrayEquals(apdu, infOf(card.sent.get(0), card.sent.get(1), card.sent.get(2)));
  }

  /** An IFSC the card cannot have meant - 0, or the reserved 0xFF - falls back to the ceiling. */
  @Test
  public void testDegenerateIfscFallsBackToTheCeiling() throws IOException {
    byte[] maximumApdu = counting(T1Block.MAX_INF_LENGTH);

    ScriptedCard zero = new ScriptedCard(OK_I_BLOCK);
    new T1Protocol(zero, 0).sendApdu(maximumApdu);
    Assert.assertEquals("IFSC 0 would never make progress", 1, zero.sent.size());

    ScriptedCard reserved = new ScriptedCard(OK_I_BLOCK);
    new T1Protocol(reserved, 0xFF).sendApdu(maximumApdu);
    Assert.assertEquals("LEN=0xFF is reserved and cannot be sent", 1, reserved.sent.size());
  }

  /**
   * Agreeing to a renegotiated IFS and then chunking at the old size would put the card straight
   * back into the position the renegotiation was meant to get it out of.
   */
  @Test
  public void testRenegotiatedIfsAppliesToLaterCommands() throws IOException {
    // The card answers the first command with an IFS request for 32 bytes
    // and then normally; the second command must respect the new size.
    ScriptedCard card =
        new ScriptedCard("00C10120E0", OK_I_BLOCK, "00800080", "00900090", OK_I_BLOCK);
    T1Protocol protocol = new T1Protocol(card, IFSC_254);

    protocol.sendApdu(Codec.fromHex(SELECT_APDU));
    protocol.sendApdu(counting(70));

    Assert.assertEquals(5, card.sent.size());
    // The S(IFS) response echoes the 32 the card proposed.
    Assert.assertArrayEquals(Codec.fromHex("00E10120C0"), card.sent.get(1));
    // The second command is chunked at 32 rather than 254.
    Assert.assertEquals((byte) 32, card.sent.get(2)[2]);
    Assert.assertEquals((byte) 32, card.sent.get(3)[2]);
    Assert.assertEquals((byte) 6, card.sent.get(4)[2]);
  }

  /** A chunk the card does not acknowledge stops the chain rather than sending on regardless. */
  @Test
  public void testUnacknowledgedChunkIsRejected() {
    // PCB=81: R-block, N(R)=0, "EDC or parity error" - a retransmission
    // request, which we do not attempt.
    ScriptedCard card = new ScriptedCard("00810081");

    try {
      new T1Protocol(card, 32).sendApdu(counting(70));
      Assert.fail("Expected IOException for an unacknowledged chunk");
    } catch (IOException e) {
      Assert.assertEquals("T=1 command chunk not acknowledged: PCB=0x81", e.getMessage());
    }
    Assert.assertEquals("Chaining must stop at the refusal", 1, card.sent.size());
  }

  /** An acknowledgement naming the wrong N(S) means the two sides disagree about the chain. */
  @Test
  public void testMisnumberedAcknowledgementIsRejected() {
    // PCB=80: N(R)=0, but we just sent N(S)=0, so the next block is N(S)=1.
    ScriptedCard card = new ScriptedCard("00800080");

    try {
      new T1Protocol(card, 32).sendApdu(counting(70));
      Assert.fail("Expected IOException for a misnumbered acknowledgement");
    } catch (IOException e) {
      Assert.assertEquals(
          "T=1 chain acknowledgement expects N(S)=0 but the next block is N(S)=1", e.getMessage());
    }
  }

  /** A card may ask for more time mid-chain, not only once the whole command is in. */
  @Test
  public void testWtxRequestDuringCommandChain() throws IOException {
    ScriptedCard card = new ScriptedCard("00C30101C3", "00900090", OK_I_BLOCK);

    byte[] response = new T1Protocol(card, 32).sendApdu(counting(40));

    Assert.assertEquals(3, card.sent.size());
    Assert.assertArrayEquals(Codec.fromHex("00E30101E3"), card.sent.get(1));
    // The extension granted, the chain picks up where it left off.
    Assert.assertEquals((byte) 8, card.sent.get(2)[2]);
    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /** We sent a complete I-block, so an R-block has nothing to acknowledge. */
  @Test
  public void testRBlockDuringResponseIsRejected() {
    ScriptedCard card = new ScriptedCard("00900090");

    try {
      new T1Protocol(card, IFSC_254).sendApdu(Codec.fromHex(SELECT_APDU));
      Assert.fail("Expected IOException for an R-block during the response read");
    } catch (IOException e) {
      Assert.assertEquals("T=1 R-block from card during response read: PCB=0x90", e.getMessage());
    }
  }

  /** An S-block control we have no answer for, here an abort request (control 0x02). */
  @Test
  public void testUnknownSBlockIsRejected() {
    ScriptedCard card = new ScriptedCard("00C200C2");

    try {
      new T1Protocol(card, IFSC_254).sendApdu(Codec.fromHex(SELECT_APDU));
      Assert.fail("Expected IOException for an unhandled S-block");
    } catch (IOException e) {
      Assert.assertEquals("Unhandled T=1 S-block from card: PCB=0xC2", e.getMessage());
    }
  }

  /** An S-block response to a request we never made is equally unactionable. */
  @Test
  public void testUnsolicitedSBlockResponseIsRejected() {
    ScriptedCard card = new ScriptedCard("00E30101E3");

    try {
      new T1Protocol(card, IFSC_254).sendApdu(Codec.fromHex(SELECT_APDU));
      Assert.fail("Expected IOException for an unsolicited S-block response");
    } catch (IOException e) {
      Assert.assertEquals("Unhandled T=1 S-block from card: PCB=0xE3", e.getMessage());
    }
  }

  /** A corrupted block surfaces from the parse rather than being reassembled into a response. */
  @Test
  public void testCorruptedBlockIsRejected() {
    ScriptedCard card = new ScriptedCard("0000029000FF");

    try {
      new T1Protocol(card, IFSC_254).sendApdu(Codec.fromHex(SELECT_APDU));
      Assert.fail("Expected IOException for LRC mismatch");
    } catch (IOException e) {
      Assert.assertEquals("T=1 LRC mismatch: got 0xFF expected 0x92", e.getMessage());
    }
  }

  /**
   * A card that keeps setting the M-bit would otherwise hold the loop open forever, so the
   * reassembly is bounded and gives up with a diagnosable error.
   */
  @Test
  public void testEndlessChainTerminates() {
    String[] endlessChain = new String[512];
    for (int i = 0; i < endlessChain.length; i++) {
      // Alternate N(S) so every block is the one our R-block asked for:
      // PCB=20 is N(S)=0 with M set, PCB=60 is N(S)=1 with M set.
      endlessChain[i] = i % 2 == 0 ? "002001AA8B" : "006001AACB";
    }
    ScriptedCard card = new ScriptedCard(endlessChain);

    try {
      new T1Protocol(card, IFSC_254).sendApdu(Codec.fromHex(SELECT_APDU));
      Assert.fail("Expected IOException once the block budget is spent");
    } catch (IOException e) {
      Assert.assertEquals("T=1 response did not terminate within 256 blocks", e.getMessage());
    }
  }
}

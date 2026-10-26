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

package com.yubico.yubikit.core.fido;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.function.IntUnaryOperator;
import org.junit.Assert;
import org.junit.Test;

/**
 * CTAPHID message framing in {@link FidoProtocol}, against a scripted authenticator.
 *
 * <p>An initialization packet carries 57 bytes and each continuation packet 59, numbered from 0.
 * The sequence number is seven bits wide, so CTAPHID ends a message at 128 continuation packets,
 * 7,609 bytes. Authenticators that send a longer message wrap the number to 0 after 127, and the
 * host has to follow them.
 */
public class FidoProtocolTest {

  private static final int CHANNEL = 0x01020304;
  private static final byte CTAPHID_CBOR = (byte) 0x90;
  private static final int INIT_PAYLOAD = 57;
  private static final int CONT_PAYLOAD = 59;

  /** A message that fills exactly 128 continuation packets, the largest CTAPHID defines. */
  private static final int SPEC_LIMIT = INIT_PAYLOAD + 128 * CONT_PAYLOAD;

  /** A length seen from a real authenticator: 232 continuation packets, wrapping once. */
  private static final int OBSERVED_LENGTH = 13708;

  /** An authenticator that answers CTAPHID_INIT and then plays back whatever a test queued. */
  private static final class Authenticator implements FidoConnection {
    private final List<byte[]> sent = new ArrayList<>();
    private final Deque<byte[]> toHost = new ArrayDeque<>();

    @Override
    public void send(byte[] packet) {
      sent.add(packet.clone());
      ByteBuffer buffer = ByteBuffer.wrap(packet);
      if (buffer.getInt() == 0xffffffff && buffer.get() == (byte) 0x86) {
        // CTAPHID_INIT: echo the nonce, then channel, protocol, version and capabilities.
        byte[] nonce = new byte[8];
        buffer.getShort(); // length
        buffer.get(nonce);
        ByteBuffer reply = ByteBuffer.allocate(17);
        reply.put(nonce).putInt(CHANNEL).put((byte) 2).put((byte) 5).put((byte) 8).put((byte) 0);
        reply.put((byte) 0x04);
        queue(0xffffffff, (byte) 0x86, reply.array(), seq -> seq & 0x7f);
      }
    }

    @Override
    public void receive(byte[] packet) throws IOException {
      byte[] next = toHost.poll();
      if (next == null) {
        throw new IOException("Authenticator has nothing more to send");
      }
      System.arraycopy(next, 0, packet, 0, packet.length);
    }

    @Override
    public void close() {}

    /** Queue a message for the host, numbering continuation packets with {@code seqOf(index)}. */
    void queue(int channel, byte cmd, byte[] payload, IntUnaryOperator seqOf) {
      ByteBuffer remaining = ByteBuffer.wrap(payload);
      byte[] packet = new byte[PACKET_SIZE];
      ByteBuffer buffer = ByteBuffer.wrap(packet);
      buffer.putInt(channel).put(cmd).putShort((short) payload.length);
      int seq = 0;
      while (true) {
        remaining.get(
            packet, buffer.position(), Math.min(remaining.remaining(), buffer.remaining()));
        toHost.add(packet.clone());
        if (!remaining.hasRemaining()) {
          return;
        }
        Arrays.fill(packet, (byte) 0);
        buffer.clear();
        buffer.putInt(channel).put((byte) seqOf.applyAsInt(seq++));
      }
    }

    /** Queue a message numbered the way CTAPHID numbers it, wrapping the sequence at 128. */
    void queue(byte[] payload) {
      queue(CHANNEL, CTAPHID_CBOR, payload, seq -> seq & 0x7f);
    }

    /** The request the host sent after the initialization exchange, reassembled. */
    byte[] request() throws IOException {
      ByteBuffer first = ByteBuffer.wrap(sent.get(1));
      Assert.assertEquals(CHANNEL, first.getInt());
      Assert.assertEquals(CTAPHID_CBOR, first.get());
      int length = first.getShort() & 0xFFFF;
      byte[] request = new byte[length];
      ByteBuffer out = ByteBuffer.wrap(request);
      out.put(sent.get(1), 7, Math.min(INIT_PAYLOAD, length));
      for (int i = 2; i < sent.size(); i++) {
        byte[] packet = sent.get(i);
        Assert.assertEquals("Channel of packet " + i, CHANNEL, ByteBuffer.wrap(packet).getInt());
        Assert.assertEquals(
            "Sequence number of continuation packet " + (i - 2), (i - 2) & 0x7f, packet[4]);
        out.put(packet, 5, Math.min(CONT_PAYLOAD, out.remaining()));
      }
      Assert.assertFalse("Request is incomplete", out.hasRemaining());
      return request;
    }
  }

  /** Bytes that differ from one position to the next, so a lost or reordered chunk shows. */
  private static byte[] pattern(int length) {
    byte[] bytes = new byte[length];
    for (int i = 0; i < length; i++) {
      bytes[i] = (byte) (i * 31 + (i >> 8) * 7 + 3);
    }
    return bytes;
  }

  private static FidoProtocol open(Authenticator authenticator) throws IOException {
    return new FidoProtocol(authenticator);
  }

  @Test
  public void testResponseAtTheCtaphidLimit() throws IOException {
    Authenticator authenticator = new Authenticator();
    FidoProtocol protocol = open(authenticator);
    byte[] expected = pattern(SPEC_LIMIT);
    authenticator.queue(expected);

    Assert.assertArrayEquals(expected, protocol.sendAndReceive(CTAPHID_CBOR, new byte[] {1}, null));
  }

  /** The first message that needs a 129th continuation packet, numbered 0 again. */
  @Test
  public void testResponseOneByteBeyondTheCtaphidLimit() throws IOException {
    Authenticator authenticator = new Authenticator();
    FidoProtocol protocol = open(authenticator);
    byte[] expected = pattern(SPEC_LIMIT + 1);
    authenticator.queue(expected);

    Assert.assertArrayEquals(expected, protocol.sendAndReceive(CTAPHID_CBOR, new byte[] {1}, null));
  }

  /** A response length seen from a real authenticator: 13,708 bytes, 232 packets, one wrap. */
  @Test
  public void testObservedLongResponse() throws IOException {
    Authenticator authenticator = new Authenticator();
    FidoProtocol protocol = open(authenticator);
    byte[] expected = pattern(OBSERVED_LENGTH);
    authenticator.queue(expected);

    Assert.assertArrayEquals(expected, protocol.sendAndReceive(CTAPHID_CBOR, new byte[] {1}, null));
  }

  /** The length field is unsigned: 40,000 reads as negative if taken as a short. */
  @Test
  public void testResponseLongerThanAShortHolds() throws IOException {
    Authenticator authenticator = new Authenticator();
    FidoProtocol protocol = open(authenticator);
    byte[] expected = pattern(40000);
    authenticator.queue(expected);

    Assert.assertArrayEquals(expected, protocol.sendAndReceive(CTAPHID_CBOR, new byte[] {1}, null));
  }

  /** The wrap is not an excuse to stop checking: a wrong number after it is still rejected. */
  @Test
  public void testWrongSequenceNumberAfterTheWrapIsRejected() throws IOException {
    Authenticator authenticator = new Authenticator();
    FidoProtocol protocol = open(authenticator);
    // 0..127, then 1 where 0 belongs.
    authenticator.queue(
        CHANNEL, CTAPHID_CBOR, pattern(OBSERVED_LENGTH), seq -> seq < 128 ? seq : seq - 127);

    try {
      protocol.sendAndReceive(CTAPHID_CBOR, new byte[] {1}, null);
      Assert.fail("Expected IOException for the wrong sequence number");
    } catch (IOException e) {
      Assert.assertEquals("Wrong sequence number. Expecting 0, Got: 1", e.getMessage());
    }
  }

  @Test
  public void testSkippedSequenceNumberIsRejected() throws IOException {
    Authenticator authenticator = new Authenticator();
    FidoProtocol protocol = open(authenticator);
    // 0, then 2: the second continuation packet is missing.
    authenticator.queue(CHANNEL, CTAPHID_CBOR, pattern(200), seq -> seq * 2);

    try {
      protocol.sendAndReceive(CTAPHID_CBOR, new byte[] {1}, null);
      Assert.fail("Expected IOException for the skipped sequence number");
    } catch (IOException e) {
      Assert.assertEquals("Wrong sequence number. Expecting 1, Got: 2", e.getMessage());
    }
  }

  /** The request side wraps the same way. */
  @Test
  public void testRequestSequenceNumberWraps() throws IOException {
    Authenticator authenticator = new Authenticator();
    FidoProtocol protocol = open(authenticator);
    authenticator.queue(new byte[] {0});
    byte[] request = pattern(OBSERVED_LENGTH);

    protocol.sendAndReceive(CTAPHID_CBOR, request, null);

    Assert.assertArrayEquals(request, authenticator.request());
  }

  @Test
  public void testLargestRepresentableRequestIsSent() throws IOException {
    Authenticator authenticator = new Authenticator();
    FidoProtocol protocol = open(authenticator);
    authenticator.queue(new byte[] {0});
    byte[] request = pattern(0xFFFF);

    protocol.sendAndReceive(CTAPHID_CBOR, request, null);

    Assert.assertArrayEquals(request, authenticator.request());
  }

  /** The length field has 16 bits; a longer request must not be silently cut to fit. */
  @Test
  public void testRequestTooLongForTheLengthFieldIsRejected() throws IOException {
    Authenticator authenticator = new Authenticator();
    FidoProtocol protocol = open(authenticator);

    try {
      protocol.sendAndReceive(CTAPHID_CBOR, pattern(0x10000), null);
      Assert.fail("Expected IllegalArgumentException for an oversized request");
    } catch (IllegalArgumentException e) {
      Assert.assertTrue(e.getMessage(), e.getMessage().contains("65536"));
    }
    Assert.assertEquals("Nothing may be sent for a rejected request", 1, authenticator.sent.size());
  }
}

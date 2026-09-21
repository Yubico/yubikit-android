/*
 * Copyright (C) 2022-2026 Yubico.
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import com.yubico.yubikit.Codec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class UsbSmartCardConnectionTest {

  /**
   * Deliberately not a legal USB bulk max packet size - real endpoints cap at 64 (full speed) or
   * 512 (high speed). The maximum-length tests stub it so a 64 KiB frame arrives in one mocked read
   * instead of a thousand-entry {@link #packetsIn} list; nothing under test reads the value except
   * the read loop's chunking, which those tests are not exercising.
   */
  private static final int OVERSIZED_MAX_PACKET_SIZE = 65536;

  /** The USB bulk max packet size every test but the two maximum-length ones runs with. */
  private static final int MAX_PACKET_SIZE = 64;

  // dwFeatures values taken from readers we have on the bench.
  private static final int FEATURES_TPDU = 0x000100BA; // Identiv SCR3500 C
  private static final int FEATURES_APDU_EXTENDED = 0x000404BA; // HID OMNIKEY 5022-CL
  private static final int FEATURES_APDU_SHORT = 0x00020000;

  /**
   * Smallest dwMaxCCIDMessageLength the host treats as usable: CCID 1.10 §5.1 requires at least the
   * 10-byte header plus a 261-byte short APDU. Anything below this is out of spec and ignored.
   * Using exactly the floor caps a command frame at 261 payload bytes, which keeps the chaining
   * tests' APDUs small enough to read.
   */
  private static final int MIN_MAX_CCID_MESSAGE_LENGTH = 271;

  /** Bytes of a command APDU that fit in one frame at {@link #MIN_MAX_CCID_MESSAGE_LENGTH}. */
  private static final int MAX_COMMAND_PAYLOAD = MIN_MAX_CCID_MESSAGE_LENGTH - 10;

  // CCID 1.10 §6.1.4 wLevelParameter, outbound.
  private static final int LEVEL_SINGLE = 0x0000;
  private static final int LEVEL_COMMAND_FIRST = 0x0001;
  private static final int LEVEL_COMMAND_LAST = 0x0002;
  private static final int LEVEL_COMMAND_MIDDLE = 0x0003;

  // CCID 1.10 §6.2.1 bChainParameter, inbound.
  private static final int CHAIN_COMPLETE = 0x00;
  private static final int CHAIN_RESPONSE_FIRST = 0x01;
  private static final int CHAIN_RESPONSE_LAST = 0x02;
  private static final int CHAIN_COMMAND_CONTINUE = 0x10;

  private final UsbDeviceConnection usbDeviceConnection = mock(UsbDeviceConnection.class);
  private final UsbInterface usbInterface = mock(UsbInterface.class);
  private final UsbEndpoint usbEndpointIn = mock(UsbEndpoint.class);
  private final UsbEndpoint usbEndpointOut = mock(UsbEndpoint.class);
  private final List<String> packetsIn = new ArrayList<>();
  private final List<byte[]> packetsOut = new ArrayList<>();

  private void assertSent(String hex) {
    Assert.assertArrayEquals("Unexpected packet sent", Codec.fromHex(hex), packetsOut.remove(0));
  }

  @Before
  public void setup() {
    when(usbEndpointIn.getMaxPacketSize()).thenReturn(MAX_PACKET_SIZE);
    when(usbEndpointOut.getMaxPacketSize()).thenReturn(MAX_PACKET_SIZE);

    when(usbDeviceConnection.bulkTransfer(eq(usbEndpointOut), any(), anyInt(), anyInt(), anyInt()))
        .then(
            invocation -> {
              byte[] buffer = invocation.getArgument(1);
              int offset = invocation.getArgument(2);
              int length = invocation.getArgument(3);
              int bytesSent = Math.min(MAX_PACKET_SIZE, length);
              packetsOut.add(Arrays.copyOfRange(buffer, offset, offset + bytesSent));
              return bytesSent;
            });

    when(usbDeviceConnection.bulkTransfer(eq(usbEndpointIn), any(), anyInt(), anyInt()))
        .then(
            invocation -> {
              byte[] buffer = invocation.getArgument(1);
              byte[] packet = Codec.fromHex(packetsIn.remove(0));
              System.arraycopy(packet, 0, buffer, 0, packet.length);
              return packet.length;
            });
  }

  @After
  public void teardown() {
    Assert.assertTrue(
        packetsIn.size() + " un-asserted packets in read buffer", packetsIn.isEmpty());
    Assert.assertTrue(
        packetsOut.size() + " un-asserted packets in sent buffer", packetsOut.isEmpty());
  }

  private UsbSmartCardConnection getConnection() throws IOException {
    // ATR - response to power on
    packetsIn.add("801700000000000000003bfd1300008131fe158073c021c057597562694b657940");
    UsbSmartCardConnection connection =
        new UsbSmartCardConnection(
            usbDeviceConnection, usbInterface, usbEndpointIn, usbEndpointOut);
    assertSent("62000000000000000000"); // Power on command
    return connection;
  }

  /**
   * A reader whose CCID class descriptor offers only the TPDU exchange level expects the host to
   * frame T=1 blocks itself. Sending it APDU-level XfrBlocks produces confusing downstream
   * failures, so the connection must refuse to open - before the power-on exchange, which is why no
   * packet is queued here.
   */
  @Test
  public void testTpduOnlyReaderIsRejected() {
    setupDescriptor(FEATURES_TPDU, MIN_MAX_CCID_MESSAGE_LENGTH);

    IOException e =
        Assert.assertThrows(
            IOException.class,
            () ->
                new UsbSmartCardConnection(
                    usbDeviceConnection, usbInterface, usbEndpointIn, usbEndpointOut));
    Assert.assertEquals(
        "Reader does not support APDU-level exchange (dwFeatures=0x000100BA, exchange level: TPDU"
            + " (host frames T=0/T=1))",
        e.getMessage());
  }

  /** A short-APDU reader is an APDU-level reader; only the TPDU-only case is refused. */
  @Test
  public void testShortApduReaderIsAccepted() throws IOException {
    setupDescriptor(FEATURES_APDU_SHORT, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    packetsIn.add("800500000000010000000102039000");
    byte[] response = connection.sendAndReceive(Codec.fromHex("0001020300"));
    assertSent("6f0500000000010000000001020300");

    Assert.assertArrayEquals(Codec.fromHex("0102039000"), response);
  }

  /** The OMNIKEY 5022-CL's dwFeatures: APDU level with extended length. */
  @Test
  public void testExtendedApduReaderIsAccepted() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    Assert.assertTrue(connection.isExtendedLengthApduSupported());

    packetsIn.add("800500000000010000000102039000");
    byte[] response = connection.sendAndReceive(Codec.fromHex("0001020300"));
    assertSent("6f0500000000010000000001020300");

    Assert.assertArrayEquals(Codec.fromHex("0102039000"), response);
  }

  /**
   * getRawDescriptors() returning null (its documented failure mode, and Mockito's default here)
   * leaves the descriptor unread. That is not an error: the connection opens and behaves as it did
   * before the descriptor was consulted at all.
   */
  @Test
  public void testNullDescriptorOpensNormally() throws IOException {
    UsbSmartCardConnection connection = getConnection();

    packetsIn.add("800500000000010000000102039000");
    byte[] response = connection.sendAndReceive(Codec.fromHex("0001020300"));
    assertSent("6f0500000000010000000001020300");

    Assert.assertArrayEquals(Codec.fromHex("0102039000"), response);
  }

  /**
   * Descriptor bytes that contain no class-specific (0x21) entry - here a lone interface descriptor
   * - must be walked to the end and then ignored, not misread as one.
   */
  @Test
  public void testDescriptorWithoutCcidEntryOpensNormally() throws IOException {
    when(usbDeviceConnection.getRawDescriptors())
        .thenReturn(Codec.fromHex("090400000204000000")); // bLength=9, bDescriptorType=0x04
    UsbSmartCardConnection connection = getConnection();

    packetsIn.add("800500000000010000000102039000");
    byte[] response = connection.sendAndReceive(Codec.fromHex("0001020300"));
    assertSent("6f0500000000010000000001020300");

    Assert.assertArrayEquals(Codec.fromHex("0102039000"), response);
  }

  @Test
  public void testSendAndReceive() throws IOException {
    UsbSmartCardConnection connection = getConnection();

    packetsIn.add("800500000000010000000102039000");
    byte[] response = connection.sendAndReceive(Codec.fromHex("0001020300"));
    assertSent("6f0500000000010000000001020300");

    Assert.assertArrayEquals(Codec.fromHex("0102039000"), response);
  }

  @Test
  public void testSendChunked() throws IOException {
    UsbSmartCardConnection connection = getConnection();

    packetsIn.add("800200000000010000009000");
    connection.sendAndReceive(
        Codec.fromHex(
            "0001000032000102030405060708090001020304050607080900010203040506070809000102030405060"
                + "7080900010203040506070809"));

    assertSent(
        "6f370000000001000000000100003200010203040506070809000102030405060708090001020304050607080"
            + "900010203040506070809000102030405060708");
    assertSent("09");
  }

  @Test
  public void testSendEmptyPacketOnExactMultiple() throws IOException {
    UsbSmartCardConnection connection = getConnection();

    packetsIn.add("800200000000010000009000");
    connection.sendAndReceive(
        Codec.fromHex(
            "0001000031000102030405060708090001020304050607080900010203040506070809000102030405060"
                + "70809000102030405060708"));

    assertSent(
        "6f360000000001000000000100003100010203040506070809000102030405060708090001020304050607080"
            + "900010203040506070809000102030405060708");
    assertSent(""); // An empty packet must be sent when the last packet ends on a boundary
  }

  /**
   * CCID 1.10 §6.2.1 response chaining. Some contactless readers (notably the HID OMNIKEY 5022-CL
   * family) split long response APDUs across multiple RDR_to_PC_DataBlock frames and signal
   * continuation via bChainParameter. The host has to fetch each subsequent chunk via a
   * PC_to_RDR_XfrBlock with wLevelParameter = 0x0010 and empty data field. This test exercises a
   * three-frame chained response: first (0x01), middle (0x03), last (0x02).
   */
  @Test
  public void testChainedResponseThreeFrames() throws IOException {
    UsbSmartCardConnection connection = getConnection();

    // First chunk: bChainParameter = 0x01 ("first part, more follows"), data = AABB.
    packetsIn.add("800200000000010000" + "01" + "AABB");
    // Middle chunk: bChainParameter = 0x03 ("middle part, more follows"), data = CCDD.
    packetsIn.add("800200000000020000" + "03" + "CCDD");
    // Last chunk: bChainParameter = 0x02 ("last part"), data = EE9000.
    packetsIn.add("800300000000030000" + "02" + "EE9000");

    byte[] response = connection.sendAndReceive(Codec.fromHex("0001020300"));

    // Initial XfrBlock carries the APDU and wLevelParameter = 0x0000.
    assertSent("6f0500000000010000000001020300");
    // Two get-next-chunk XfrBlocks with empty data field and wLevelParameter = 0x0010 (LE: 1000).
    assertSent("6f000000000002001000");
    assertSent("6f000000000003001000");

    Assert.assertArrayEquals(Codec.fromHex("AABBCCDDEE9000"), response);
  }

  /**
   * Two-frame chained response: first (0x01) then last (0x02), with no middle block in between.
   * Readers only emit a middle block for responses spanning three or more frames, so this is the
   * common chaining shape.
   */
  @Test
  public void testChainedResponseTwoFrames() throws IOException {
    UsbSmartCardConnection connection = getConnection();

    // First chunk: bChainParameter = 0x01 ("first part, more follows"), data = AABB.
    packetsIn.add("800200000000010000" + "01" + "AABB");
    // Last chunk: bChainParameter = 0x02 ("last part"), data = CC9000.
    packetsIn.add("800300000000020000" + "02" + "CC9000");

    byte[] response = connection.sendAndReceive(Codec.fromHex("0001020300"));

    assertSent("6f0500000000010000000001020300");
    // A single get-next-chunk XfrBlock with wLevelParameter = 0x0010 (LE: 1000).
    assertSent("6f000000000002001000");

    Assert.assertArrayEquals(Codec.fromHex("AABBCC9000"), response);
  }

  /**
   * bChainParameter = 0x02 ("last part") on the very first reply. Some readers report the final
   * chunk without ever announcing a first chunk, so the host must accept the response as-is instead
   * of waiting for a 0x01 to start the chain.
   */
  @Test
  public void testChainedResponseLastWithoutFirst() throws IOException {
    UsbSmartCardConnection connection = getConnection();

    packetsIn.add("800500000000010000" + "02" + "0102039000");

    byte[] response = connection.sendAndReceive(Codec.fromHex("0001020300"));

    assertSent("6f0500000000010000000001020300");

    Assert.assertArrayEquals(Codec.fromHex("0102039000"), response);
  }

  /**
   * bChainParameter = 0x00 ("complete") must not enter the chaining loop at all. Two consecutive
   * exchanges are sent so the bSeq of the second one (0x02, not 0x03) proves no extra XfrBlock was
   * spent fetching a chunk that was never announced.
   */
  @Test
  public void testUnchainedResponse() throws IOException {
    UsbSmartCardConnection connection = getConnection();

    packetsIn.add("800500000000010000" + "00" + "0102039000");
    byte[] first = connection.sendAndReceive(Codec.fromHex("0001020300"));
    assertSent("6f0500000000010000000001020300");
    Assert.assertArrayEquals(Codec.fromHex("0102039000"), first);

    packetsIn.add("800200000000020000" + "00" + "9000");
    byte[] second = connection.sendAndReceive(Codec.fromHex("0001020300"));
    assertSent("6f0500000000020000000001020300");
    Assert.assertArrayEquals(Codec.fromHex("9000"), second);
  }

  /**
   * A reader that announces "more follows" (0x03) but returns an empty chunk makes no progress. The
   * chaining loop must give up instead of asking for the same nothing forever.
   */
  @Test
  public void testChainedResponseEmptyContinuationChunk() throws IOException {
    UsbSmartCardConnection connection = getConnection();

    packetsIn.add("800200000000010000" + "01" + "AABB");
    // dwLength = 0, bChainParameter = 0x03: header only, no data.
    packetsIn.add("800000000000020000" + "03");

    IOException e =
        Assert.assertThrows(
            IOException.class, () -> connection.sendAndReceive(Codec.fromHex("0001020300")));
    Assert.assertEquals("Empty continuation chunk in chained response", e.getMessage());

    assertSent("6f0500000000010000000001020300");
    assertSent("6f000000000002001000");
  }

  /**
   * The reader, not the host, decides how many chunks to send, so the reassembled response is
   * capped at the largest response APDU ISO 7816-4 can express (65536 + SW1SW2). Exactly that many
   * bytes must still be accepted.
   */
  @Test
  public void testChainedResponseAtMaximumLength() throws IOException {
    when(usbEndpointIn.getMaxPacketSize()).thenReturn(OVERSIZED_MAX_PACKET_SIZE);
    UsbSmartCardConnection connection = getConnection();

    // 65520 bytes (dwLength = 0x0000FFF0), bChainParameter = 0x01.
    packetsIn.add("80F0FF0000" + "00" + "01" + "0000" + "01" + repeatHex("AA", 65520));
    // 18 more bytes brings the total to exactly 65538; bChainParameter = 0x02 ends the chain.
    packetsIn.add("801200000000020000" + "02" + repeatHex("BB", 18));

    byte[] response = connection.sendAndReceive(Codec.fromHex("0001020300"));

    assertSent("6f0500000000010000000001020300");
    assertSent("6f000000000002001000");

    Assert.assertEquals(65538, response.length);
    Assert.assertArrayEquals(Codec.fromHex(repeatHex("AA", 65520) + repeatHex("BB", 18)), response);
  }

  /** One byte past the cap must be rejected rather than grown into. */
  @Test
  public void testChainedResponseOverMaximumLength() throws IOException {
    when(usbEndpointIn.getMaxPacketSize()).thenReturn(OVERSIZED_MAX_PACKET_SIZE);
    UsbSmartCardConnection connection = getConnection();

    packetsIn.add("80F0FF0000" + "00" + "01" + "0000" + "01" + repeatHex("AA", 65520));
    // 19 bytes would make 65539, one over the limit.
    packetsIn.add("801300000000020000" + "02" + repeatHex("BB", 19));

    IOException e =
        Assert.assertThrows(
            IOException.class, () -> connection.sendAndReceive(Codec.fromHex("0001020300")));
    Assert.assertEquals("Chained response exceeds 65538 bytes", e.getMessage());

    assertSent("6f0500000000010000000001020300");
    assertSent("6f000000000002001000");
  }

  // ---------------------------------------------------------------
  // CCID 1.10 §6.1.4 outbound command chaining
  //
  // A reader advertises the largest CCID message it accepts in
  // dwMaxCCIDMessageLength. A command APDU that does not fit has to be
  // split across several PC_to_RDR_XfrBlock messages tagged via
  // wLevelParameter, each non-final one acknowledged by the reader with
  // bChainParameter = 0x10. All these tests advertise the spec floor
  // (271), so one frame carries at most 261 payload bytes.
  // ---------------------------------------------------------------

  /** An APDU of exactly the per-frame limit must still go out as one unchained frame. */
  @Test
  public void testCommandFitsExactly() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(MAX_COMMAND_PAYLOAD);
    packetsIn.add(dataBlock(1, CHAIN_COMPLETE, Codec.fromHex("9000")));

    byte[] response = connection.sendAndReceive(apdu);

    assertSentFrame(xfrBlock(1, LEVEL_SINGLE, apdu));
    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /** One byte past the limit is the boundary that has to chain: 261 + 1. */
  @Test
  public void testCommandOneByteOver() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(MAX_COMMAND_PAYLOAD + 1);
    packetsIn.add(dataBlock(1, CHAIN_COMMAND_CONTINUE, new byte[0]));
    packetsIn.add(dataBlock(2, CHAIN_COMPLETE, Codec.fromHex("9000")));

    byte[] response = connection.sendAndReceive(apdu);

    assertSentFrame(xfrBlock(1, LEVEL_COMMAND_FIRST, slice(apdu, 0, MAX_COMMAND_PAYLOAD)));
    assertSentFrame(xfrBlock(2, LEVEL_COMMAND_LAST, slice(apdu, MAX_COMMAND_PAYLOAD, 1)));
    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /** Three frames exercise the middle tag (0x0003), which two frames never produce. */
  @Test
  public void testCommandThreeFrames() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(600);
    packetsIn.add(dataBlock(1, CHAIN_COMMAND_CONTINUE, new byte[0]));
    packetsIn.add(dataBlock(2, CHAIN_COMMAND_CONTINUE, new byte[0]));
    packetsIn.add(dataBlock(3, CHAIN_COMPLETE, Codec.fromHex("9000")));

    byte[] response = connection.sendAndReceive(apdu);

    assertSentFrame(xfrBlock(1, LEVEL_COMMAND_FIRST, slice(apdu, 0, 261)));
    assertSentFrame(xfrBlock(2, LEVEL_COMMAND_MIDDLE, slice(apdu, 261, 261)));
    assertSentFrame(xfrBlock(3, LEVEL_COMMAND_LAST, slice(apdu, 522, 78)));
    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /**
   * Frame-shape assertions can pass while the payload is subtly wrong - a chunk taken from the
   * wrong offset, or one emitted twice. This strips the headers off whatever was sent and requires
   * the concatenation to be the original APDU, byte for byte.
   */
  @Test
  public void testCommandChunksReassemble() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(700);
    packetsIn.add(dataBlock(1, CHAIN_COMMAND_CONTINUE, new byte[0]));
    packetsIn.add(dataBlock(2, CHAIN_COMMAND_CONTINUE, new byte[0]));
    packetsIn.add(dataBlock(3, CHAIN_COMPLETE, Codec.fromHex("9000")));

    connection.sendAndReceive(apdu);

    ByteArrayOutputStream reassembled = new ByteArrayOutputStream();
    for (byte[] frame : drainSentFrames()) {
      reassembled.write(frame, 10, frame.length - 10);
    }
    Assert.assertArrayEquals(apdu, reassembled.toByteArray());
  }

  /**
   * Every chunk is a CCID message in its own right, so bSeq must advance once per chunk - not once
   * per APDU. The exchange after the chained one proves the counter was left where the reader
   * expects it.
   */
  @Test
  public void testCommandChainSequenceNumbers() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(600);
    packetsIn.add(dataBlock(1, CHAIN_COMMAND_CONTINUE, new byte[0]));
    packetsIn.add(dataBlock(2, CHAIN_COMMAND_CONTINUE, new byte[0]));
    packetsIn.add(dataBlock(3, CHAIN_COMPLETE, Codec.fromHex("9000")));
    connection.sendAndReceive(apdu);

    assertSentFrame(xfrBlock(1, LEVEL_COMMAND_FIRST, slice(apdu, 0, 261)));
    assertSentFrame(xfrBlock(2, LEVEL_COMMAND_MIDDLE, slice(apdu, 261, 261)));
    assertSentFrame(xfrBlock(3, LEVEL_COMMAND_LAST, slice(apdu, 522, 78)));

    // A short APDU straight after: bSeq continues at 4, not back at 2.
    byte[] small = Codec.fromHex("0001020300");
    packetsIn.add(dataBlock(4, CHAIN_COMPLETE, Codec.fromHex("9000")));
    connection.sendAndReceive(small);
    assertSentFrame(xfrBlock(4, LEVEL_SINGLE, small));
  }

  /**
   * The acknowledgement to a non-final chunk is a DataBlock like any other, so its data field must
   * not be mistaken for part of the response APDU. Real readers send it empty; this one echoes
   * bytes back, which the spec does not forbid and the host must discard either way.
   */
  @Test
  public void testCommandChainAckChainParameter() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(300);
    packetsIn.add(dataBlock(1, CHAIN_COMMAND_CONTINUE, Codec.fromHex("DEADBEEF")));
    packetsIn.add(dataBlock(2, CHAIN_COMPLETE, Codec.fromHex("0102039000")));

    byte[] response = connection.sendAndReceive(apdu);

    assertSentFrame(xfrBlock(1, LEVEL_COMMAND_FIRST, slice(apdu, 0, 261)));
    assertSentFrame(xfrBlock(2, LEVEL_COMMAND_LAST, slice(apdu, 261, 39)));

    // Only the reply to the final chunk is the response APDU.
    Assert.assertArrayEquals(Codec.fromHex("0102039000"), response);
  }

  /**
   * A reader that answers a non-final chunk with anything but "continuation expected" believes the
   * command is already complete, so the bytes still queued would be dropped on the floor and the
   * card would answer a truncated APDU. Fail loudly instead.
   */
  @Test
  public void testCommandChainRejectsBadAck() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(300);
    packetsIn.add(dataBlock(1, CHAIN_COMPLETE, Codec.fromHex("9000")));

    IOException e = Assert.assertThrows(IOException.class, () -> connection.sendAndReceive(apdu));
    Assert.assertEquals(
        "Reader did not acknowledge chained command chunk: bChainParameter=0x00", e.getMessage());

    assertSentFrame(xfrBlock(1, LEVEL_COMMAND_FIRST, slice(apdu, 0, 261)));
  }

  /**
   * A chunk whose frame length lands on a USB packet boundary still needs the zero-length packet
   * that terminates a bulk transfer - the split must not swallow it. Here the last chunk's frame is
   * 256 bytes, exactly four full packets.
   */
  @Test
  public void testCommandChainExactMultipleZlp() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(261 + 246);
    packetsIn.add(dataBlock(1, CHAIN_COMMAND_CONTINUE, new byte[0]));
    packetsIn.add(dataBlock(2, CHAIN_COMPLETE, Codec.fromHex("9000")));

    connection.sendAndReceive(apdu);

    // 271 bytes: not a multiple of 64, so no trailing empty packet.
    assertSentFrame(xfrBlock(1, LEVEL_COMMAND_FIRST, slice(apdu, 0, 261)));
    // 256 bytes: assertSentFrame consumes the empty packet that must follow.
    assertSentFrame(xfrBlock(2, LEVEL_COMMAND_LAST, slice(apdu, 261, 246)));
  }

  /**
   * Both directions chain in the same exchange. The command goes out in two frames and the reply to
   * the final one is itself chained, so the response loop has to pick up where the command loop
   * left off rather than returning the first chunk.
   */
  @Test
  public void testCommandAndResponseChaining() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(300);
    packetsIn.add(dataBlock(1, CHAIN_COMMAND_CONTINUE, new byte[0]));
    packetsIn.add(dataBlock(2, CHAIN_RESPONSE_FIRST, Codec.fromHex("AABB")));
    packetsIn.add(dataBlock(3, CHAIN_RESPONSE_LAST, Codec.fromHex("CC9000")));

    byte[] response = connection.sendAndReceive(apdu);

    assertSentFrame(xfrBlock(1, LEVEL_COMMAND_FIRST, slice(apdu, 0, 261)));
    assertSentFrame(xfrBlock(2, LEVEL_COMMAND_LAST, slice(apdu, 261, 39)));
    // Get-next-chunk XfrBlock: empty data, wLevelParameter = 0x0010.
    assertSentFrame(xfrBlock(3, 0x0010, new byte[0]));

    Assert.assertArrayEquals(Codec.fromHex("AABBCC9000"), response);
  }

  /**
   * The size that motivated this work: a 1200-byte extended APDU over the OMNIKEY 5022-CL, which
   * advertises 520 bytes. Modelled at the spec floor instead, so it takes five frames rather than
   * three - same code path, fewer bytes to read in the assertions.
   */
  @Test
  public void testCtapSizedCommandOverSmallBuffer() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, MIN_MAX_CCID_MESSAGE_LENGTH);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(1200);
    for (int seq = 1; seq <= 4; seq++) {
      packetsIn.add(dataBlock(seq, CHAIN_COMMAND_CONTINUE, new byte[0]));
    }
    packetsIn.add(dataBlock(5, CHAIN_COMPLETE, Codec.fromHex("9000")));

    byte[] response = connection.sendAndReceive(apdu);

    assertSentFrame(xfrBlock(1, LEVEL_COMMAND_FIRST, slice(apdu, 0, 261)));
    assertSentFrame(xfrBlock(2, LEVEL_COMMAND_MIDDLE, slice(apdu, 261, 261)));
    assertSentFrame(xfrBlock(3, LEVEL_COMMAND_MIDDLE, slice(apdu, 522, 261)));
    assertSentFrame(xfrBlock(4, LEVEL_COMMAND_MIDDLE, slice(apdu, 783, 261)));
    assertSentFrame(xfrBlock(5, LEVEL_COMMAND_LAST, slice(apdu, 1044, 156)));

    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /** A reader with room to spare must keep getting one frame tagged 0x0000, as before. */
  @Test
  public void testNoChainingWhenBufferLarge() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, 4096);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(2048);
    packetsIn.add(dataBlock(1, CHAIN_COMPLETE, Codec.fromHex("9000")));

    byte[] response = connection.sendAndReceive(apdu);

    assertSentFrame(xfrBlock(1, LEVEL_SINGLE, apdu));
    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /**
   * No CCID class descriptor means no dwMaxCCIDMessageLength to chunk by. Assume the APDU fits,
   * which is what this class did unconditionally before chaining existed.
   */
  @Test
  public void testNoChainingWithoutDescriptor() throws IOException {
    // getRawDescriptors() returns null by default from Mockito (no stubbing).
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(1000);
    packetsIn.add(dataBlock(1, CHAIN_COMPLETE, Codec.fromHex("9000")));

    byte[] response = connection.sendAndReceive(apdu);

    assertSentFrame(xfrBlock(1, LEVEL_SINGLE, apdu));
    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  /**
   * A reader advertising less than the CCID 1.10 §5.1 floor is out of spec. Chunking by a value
   * that small would emit an absurd number of frames - and by zero, one frame per byte - so the
   * field is ignored and the APDU goes out whole.
   */
  @Test
  public void testDegenerateMaxMessageLength() throws IOException {
    setupDescriptor(FEATURES_APDU_EXTENDED, 64);
    UsbSmartCardConnection connection = getConnection();

    byte[] apdu = filler(1000);
    packetsIn.add(dataBlock(1, CHAIN_COMPLETE, Codec.fromHex("9000")));

    byte[] response = connection.sendAndReceive(apdu);

    assertSentFrame(xfrBlock(1, LEVEL_SINGLE, apdu));
    Assert.assertArrayEquals(Codec.fromHex("9000"), response);
  }

  // ---------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------

  /**
   * Assert that the next CCID frame written to the bulk-OUT endpoint is {@code hex}, reassembling
   * it from however many {@value #MAX_PACKET_SIZE}-byte USB packets it took. When the frame length
   * is an exact multiple of the packet size the terminating zero-length packet is consumed too.
   */
  private void assertSentFrame(String hex) {
    byte[] expected = Codec.fromHex(hex);
    byte[] actual = nextSentFrame(expected.length);
    if (expected.length % MAX_PACKET_SIZE == 0) {
      Assert.assertFalse("Missing zero-length packet after frame", packetsOut.isEmpty());
      Assert.assertEquals(
          "Frame ends on a packet boundary and must be followed by an empty packet",
          0,
          packetsOut.remove(0).length);
    }
    Assert.assertArrayEquals("Unexpected frame sent", expected, actual);
  }

  /** Pop packets off the sent buffer until {@code length} bytes have been collected. */
  private byte[] nextSentFrame(int length) {
    ByteArrayOutputStream frame = new ByteArrayOutputStream();
    while (frame.size() < length) {
      Assert.assertFalse(
          "Ran out of sent packets after " + frame.size() + " of " + length + " bytes",
          packetsOut.isEmpty());
      byte[] packet = packetsOut.remove(0);
      Assert.assertNotEquals("Empty packet in the middle of a frame", 0, packet.length);
      frame.write(packet, 0, packet.length);
    }
    return frame.toByteArray();
  }

  /**
   * Drain the whole sent buffer into one frame per CCID message, reading each frame's length out of
   * its own dwLength field. Used where the assertion is about the payload rather than the frame
   * shape.
   */
  private List<byte[]> drainSentFrames() {
    List<byte[]> frames = new ArrayList<>();
    while (!packetsOut.isEmpty()) {
      // Peek the header to learn how long this frame is: 10-byte prefix
      // plus dwLength at offset 1 (little-endian uint32).
      byte[] first = packetsOut.get(0);
      Assert.assertTrue("Packet too short to hold a CCID header", first.length >= 10);
      int dataLength =
          (first[1] & 0xFF)
              | ((first[2] & 0xFF) << 8)
              | ((first[3] & 0xFF) << 16)
              | ((first[4] & 0xFF) << 24);
      int frameLength = 10 + dataLength;
      frames.add(nextSentFrame(frameLength));
      if (frameLength % MAX_PACKET_SIZE == 0 && !packetsOut.isEmpty()) {
        Assert.assertEquals(
            "Frame ends on a packet boundary and must be followed by an empty packet",
            0,
            packetsOut.remove(0).length);
      }
    }
    return frames;
  }

  /** Hex for a PC_to_RDR_XfrBlock: 10-byte header with wLevelParameter, then the payload. */
  private static String xfrBlock(int sequence, int wLevelParameter, byte[] payload) {
    return "6f"
        + le32(payload.length)
        + "00" // bSlot
        + u8(sequence)
        + "00" // bBWI
        + le16(wLevelParameter)
        + toHex(payload);
  }

  /** Hex for an RDR_to_PC_DataBlock: 10-byte header with bChainParameter, then the data. */
  private static String dataBlock(int sequence, int chainParameter, byte[] data) {
    return "80"
        + le32(data.length)
        + "00" // bSlot
        + u8(sequence)
        + "00" // bStatus
        + "00" // bError
        + u8(chainParameter)
        + toHex(data);
  }

  private void setupDescriptor(int dwFeatures, int dwMaxCcidMessageLength) {
    when(usbDeviceConnection.getRawDescriptors())
        .thenReturn(Codec.fromHex(descriptorHex(dwFeatures, dwMaxCcidMessageLength)));
  }

  /**
   * A 54-byte CCID class descriptor (bLength=0x36, bDescriptorType=0x21). Only dwFeatures at offset
   * 40 and dwMaxCCIDMessageLength at offset 44 are read by the code under test; every other field
   * is a plausible-but-irrelevant constant.
   */
  private static String descriptorHex(int dwFeatures, int dwMaxCcidMessageLength) {
    return "36211001" // bLength, bDescriptorType, bcdCCID
        + "0001" // bMaxSlotIndex, bVoltageSupport
        + "02000000" // dwProtocols
        + "A00F0000" // dwDefaultClock
        + "A00F0000" // dwMaximumClock
        + "00" // bNumClockSupported
        + "80250000" // dwDataRate
        + "80250000" // dwMaxDataRate
        + "00" // bNumDataRatesSupported
        + "FE000000" // dwMaxIFSD
        + "00000000" // dwSynchProtocols
        + "00000000" // dwMechanical
        + le32(dwFeatures)
        + le32(dwMaxCcidMessageLength)
        + "FFFF" // bClassGetResponse, bClassEnvelope
        + "0000" // wLcdLayout
        + "0001"; // bPINSupport, bMaxCCIDBusySlots
  }

  /**
   * {@code length} bytes with a period of 65536 rather than 256, so a chunk copied from the wrong
   * offset cannot compare equal to the one that belongs there.
   */
  private static byte[] filler(int length) {
    byte[] bytes = new byte[length];
    for (int i = 0; i < length; i++) {
      bytes[i] = (byte) (i ^ (i >> 8));
    }
    return bytes;
  }

  private static byte[] slice(byte[] bytes, int offset, int length) {
    return Arrays.copyOfRange(bytes, offset, offset + length);
  }

  private static String u8(int value) {
    return String.format(Locale.ROOT, "%02x", value & 0xFF);
  }

  private static String le16(int value) {
    return u8(value) + u8(value >> 8);
  }

  private static String le32(int value) {
    return le16(value) + le16(value >> 16);
  }

  private static String toHex(byte[] bytes) {
    StringBuilder builder = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      builder.append(u8(b));
    }
    return builder.toString();
  }

  private static String repeatHex(String byteHex, int count) {
    StringBuilder builder = new StringBuilder(byteHex.length() * count);
    for (int i = 0; i < count; i++) {
      builder.append(byteHex);
    }
    return builder.toString();
  }
}

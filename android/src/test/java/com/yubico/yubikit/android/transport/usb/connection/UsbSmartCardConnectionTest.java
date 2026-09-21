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
    when(usbEndpointIn.getMaxPacketSize()).thenReturn(64);
    when(usbEndpointOut.getMaxPacketSize()).thenReturn(64);

    when(usbDeviceConnection.bulkTransfer(eq(usbEndpointOut), any(), anyInt(), anyInt(), anyInt()))
        .then(
            invocation -> {
              byte[] buffer = invocation.getArgument(1);
              int offset = invocation.getArgument(2);
              int length = invocation.getArgument(3);
              int bytesSent = Math.min(64, length);
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

  private static String u8(int value) {
    return String.format(Locale.ROOT, "%02x", value & 0xFF);
  }

  private static String le16(int value) {
    return u8(value) + u8(value >> 8);
  }

  private static String le32(int value) {
    return le16(value) + le16(value >> 16);
  }

  private static String repeatHex(String byteHex, int count) {
    StringBuilder builder = new StringBuilder(byteHex.length() * count);
    for (int i = 0; i < count; i++) {
      builder.append(byteHex);
    }
    return builder.toString();
  }
}

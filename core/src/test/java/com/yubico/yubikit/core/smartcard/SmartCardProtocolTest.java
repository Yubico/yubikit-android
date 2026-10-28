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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import org.junit.Test;

public class SmartCardProtocolTest {

  // An extended APDU consists of a header, the extended length marker and length, and the data.
  private static final int EXTENDED_OVERHEAD = 4 + 3;

  private static final int CHAINED_CLA_FLAG = 0x10;
  private static final int SHORT_CHUNK = 255;

  private static final Version YK_5_7_2 = new Version(5, 7, 2);
  private static final Version YK6 = new Version(6, 0, 0);

  private static final byte[] OK = {(byte) 0x90, 0x00};

  private static class RecordingConnection implements SmartCardConnection {
    final List<byte[]> sent = new ArrayList<>();
    // responses to use for the APDUs sent, in order, until empty after which OK is used
    final Deque<byte[]> responses = new ArrayDeque<>();

    @Override
    public byte[] sendAndReceive(byte[] apdu) {
      sent.add(apdu);
      byte[] response = responses.poll();
      return response != null ? response : OK;
    }

    @Override
    public Transport getTransport() {
      return Transport.USB;
    }

    @Override
    public boolean isExtendedLengthApduSupported() {
      return true;
    }

    @Override
    public byte[] getAtr() {
      return new byte[0];
    }

    @Override
    public void close() throws IOException {}
  }

  private static byte[] pattern(int length) {
    byte[] data = new byte[length];
    for (int i = 0; i < length; i++) {
      data[i] = (byte) (i * 31 + 7);
    }
    return data;
  }

  private static SmartCardProtocol protocolFor(RecordingConnection connection, Version version)
      throws IOException {
    SmartCardProtocol protocol = new SmartCardProtocol(connection);
    protocol.configure(version);
    return protocol;
  }

  private static int chunksFor(int dataLength) {
    return (dataLength + SHORT_CHUNK - 1) / SHORT_CHUNK;
  }

  /** The command data of a short APDU. */
  private static byte[] shortApduData(byte[] apdu) {
    int length = apdu[4] & 0xff;
    return Arrays.copyOfRange(apdu, 5, 5 + length);
  }

  /** Verifies that the data was sent as a chain of short APDUs, and returns the sent data. */
  private static byte[] assertSentAsShortChain(
      List<byte[]> sent, int expectedChunks, int cla, int ins, int p1, int p2) {
    assertEquals(expectedChunks, sent.size());
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    for (int i = 0; i < sent.size(); i++) {
      byte[] apdu = sent.get(i);
      boolean last = i == sent.size() - 1;
      assertTrue("Not a short APDU", apdu.length <= 261);
      assertEquals(last ? cla : cla | CHAINED_CLA_FLAG, apdu[0] & 0xff);
      assertEquals(ins, apdu[1] & 0xff);
      assertEquals(p1, apdu[2] & 0xff);
      assertEquals(p2, apdu[3] & 0xff);
      byte[] chunk = shortApduData(apdu);
      assertEquals(last ? chunk.length : SHORT_CHUNK, chunk.length);
      data.write(chunk, 0, chunk.length);
    }
    return data.toByteArray();
  }

  @Test
  public void apduUpToTheLimitIsSentInOnePiece() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK_5_7_2);

    protocol.sendAndReceive(
        new Apdu(0, 0x01, 0, 0, new byte[MaxApduSize.YK4_3 - EXTENDED_OVERHEAD]));

    assertEquals(1, connection.sent.size());
    assertEquals(MaxApduSize.YK4_3, connection.sent.get(0).length);
  }

  @Test
  public void apduBeyondTheLimitIsChained() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK_5_7_2);

    // one byte more than fits in an extended APDU
    byte[] data = pattern(MaxApduSize.YK4_3 - EXTENDED_OVERHEAD + 1);
    protocol.sendAndReceive(new Apdu(0, 0x01, 0x02, 0x03, data));

    byte[] sentData =
        assertSentAsShortChain(connection.sent, chunksFor(data.length), 0, 0x01, 0x02, 0x03);
    assertArrayEquals(data, sentData);
  }

  @Test
  public void shortDataIsNeverChained() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK_5_7_2);

    protocol.sendAndReceive(new Apdu(0, 0x01, 0, 0, new byte[SHORT_CHUNK]));

    // sent as an extended APDU, which has the extended length marker after the header
    assertEquals(1, connection.sent.size());
    assertEquals(0, connection.sent.get(0)[4]);
    assertEquals(EXTENDED_OVERHEAD + SHORT_CHUNK, connection.sent.get(0).length);
  }

  @Test
  public void largerApduIsSentInOnePieceWhenSupported() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK6);

    // more than the earlier limit
    protocol.sendAndReceive(new Apdu(0, 0x01, 0, 0, new byte[4_000]));

    assertEquals(1, connection.sent.size());
    assertEquals(EXTENDED_OVERHEAD + 4_000, connection.sent.get(0).length);
  }

  @Test
  public void apduBeyondTheLargerLimitIsChained() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK6);

    protocol.sendAndReceive(new Apdu(0, 0x01, 0, 0, new byte[MaxApduSize.YK6 - EXTENDED_OVERHEAD]));
    assertEquals(1, connection.sent.size());
    assertEquals(MaxApduSize.YK6, connection.sent.get(0).length);

    connection.sent.clear();
    byte[] data = pattern(MaxApduSize.YK6 - EXTENDED_OVERHEAD + 1);
    protocol.sendAndReceive(new Apdu(0, 0x01, 0, 0, data));

    byte[] sentData =
        assertSentAsShortChain(connection.sent, chunksFor(data.length), 0, 0x01, 0, 0);
    assertArrayEquals(data, sentData);
  }

  @Test
  public void chainingKeepsTheClassOfTheCommand() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK_5_7_2);

    byte[] data = pattern(5_000);
    protocol.sendAndReceive(new Apdu(0x80, 0x01, 0x04, 0x05, data));

    byte[] sentData =
        assertSentAsShortChain(connection.sent, chunksFor(data.length), 0x80, 0x01, 0x04, 0x05);
    assertArrayEquals(data, sentData);
  }

  @Test
  public void chainStopsAtTheFirstError() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    connection.responses.add(OK);
    connection.responses.add(new byte[] {0x69, (byte) 0x82});
    SmartCardProtocol protocol = protocolFor(connection, YK_5_7_2);

    ApduException e =
        assertThrows(
            ApduException.class,
            () -> protocol.sendAndReceive(new Apdu(0, 0x01, 0, 0, pattern(5_000))));

    assertEquals(0x6982, e.getSw());
    assertEquals(2, connection.sent.size());
  }

  @Test
  public void responseOfTheLastChunkIsReturned() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    int chunks = chunksFor(5_000);
    for (int i = 0; i < chunks - 1; i++) {
      connection.responses.add(OK);
    }
    connection.responses.add(new byte[] {0x01, 0x02, 0x03, (byte) 0x90, 0x00});
    SmartCardProtocol protocol = protocolFor(connection, YK_5_7_2);

    byte[] response = protocol.sendAndReceive(new Apdu(0, 0x01, 0, 0, pattern(5_000)));

    assertArrayEquals(new byte[] {0x01, 0x02, 0x03}, response);
  }

  @Test
  public void leBeyondAShortApduIsLeftOutWhenChaining() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK_5_7_2);

    byte[] data = pattern(3_500);
    protocol.sendAndReceive(new Apdu(0, 0x01, 0, 0, data, 1_000));

    assertEquals(chunksFor(data.length), connection.sent.size());
    byte[] last = connection.sent.get(connection.sent.size() - 1);
    // header, length and data only, without Le
    assertEquals(5 + shortApduData(last).length, last.length);
  }

  @Test
  public void leWithinAShortApduIsKeptWhenChaining() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK_5_7_2);

    byte[] data = pattern(3_500);
    protocol.sendAndReceive(new Apdu(0, 0x01, 0, 0, data, 200));

    byte[] last = connection.sent.get(connection.sent.size() - 1);
    assertEquals(5 + shortApduData(last).length + 1, last.length);
    assertEquals((byte) 200, last[last.length - 1]);
  }

  @Test
  public void forcedShortApdusAreChained() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = new SmartCardProtocol(connection);
    protocol.configure(
        YK6, new SmartCardProtocol.Configuration.Builder().setForceShortApdus(true).build());

    byte[] data = pattern(600);
    protocol.sendAndReceive(new Apdu(0, 0x01, 0, 0, data));

    byte[] sentData = assertSentAsShortChain(connection.sent, 3, 0, 0x01, 0, 0);
    assertArrayEquals(data, sentData);
  }
}

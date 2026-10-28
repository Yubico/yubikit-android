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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public class SmartCardProtocolTest {

  // An extended APDU consists of a header, the extended length marker and length, and the data.
  private static final int EXTENDED_OVERHEAD = 4 + 3;

  private static final Version YK_5_7_2 = new Version(5, 7, 2);
  private static final Version YK6 = new Version(6, 0, 0);

  private static class RecordingConnection implements SmartCardConnection {
    final List<byte[]> sent = new ArrayList<>();

    @Override
    public byte[] sendAndReceive(byte[] apdu) {
      sent.add(apdu);
      return new byte[] {(byte) 0x90, 0x00};
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

  private static Apdu apduWithData(int length) {
    return new Apdu(0, 0x01, 0, 0, new byte[length]);
  }

  private static SmartCardProtocol protocolFor(RecordingConnection connection, Version version)
      throws IOException {
    SmartCardProtocol protocol = new SmartCardProtocol(connection);
    protocol.configure(version);
    return protocol;
  }

  @Test
  public void apduUpToTheLimitIsSentInOnePiece() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK_5_7_2);

    protocol.sendAndReceive(apduWithData(MaxApduSize.YK4_3 - EXTENDED_OVERHEAD));

    assertEquals(1, connection.sent.size());
    assertEquals(MaxApduSize.YK4_3, connection.sent.get(0).length);
  }

  @Test
  public void apduBeyondTheLimitIsRejected() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK_5_7_2);

    assertThrows(
        UnsupportedOperationException.class,
        () -> protocol.sendAndReceive(apduWithData(MaxApduSize.YK4_3 - EXTENDED_OVERHEAD + 1)));
    assertTrue(connection.sent.isEmpty());
  }

  @Test
  public void largerApduIsSentInOnePieceWhenSupported() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK6);

    // more than the earlier limit
    protocol.sendAndReceive(apduWithData(4_000));

    assertEquals(1, connection.sent.size());
    assertEquals(EXTENDED_OVERHEAD + 4_000, connection.sent.get(0).length);
  }

  @Test
  public void largerLimitIsStillEnforced() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = protocolFor(connection, YK6);

    protocol.sendAndReceive(apduWithData(MaxApduSize.YK6 - EXTENDED_OVERHEAD));
    assertEquals(1, connection.sent.size());

    assertThrows(
        UnsupportedOperationException.class,
        () -> protocol.sendAndReceive(apduWithData(MaxApduSize.YK6 - EXTENDED_OVERHEAD + 1)));
    assertEquals(1, connection.sent.size());
  }

  @Test
  public void forcedShortApdusAreChained() throws Exception {
    RecordingConnection connection = new RecordingConnection();
    SmartCardProtocol protocol = new SmartCardProtocol(connection);
    protocol.configure(
        YK6, new SmartCardProtocol.Configuration.Builder().setForceShortApdus(true).build());

    protocol.sendAndReceive(apduWithData(600));

    // short APDUs carry at most 255 bytes of data, the rest is sent with command chaining
    assertEquals(3, connection.sent.size());
    for (byte[] apdu : connection.sent) {
      assertTrue(apdu.length <= 261);
    }
  }
}

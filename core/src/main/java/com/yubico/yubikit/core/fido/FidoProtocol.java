/*
 * Copyright (C) 2020-2026 Yubico.
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

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.core.util.StringUtils;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FidoProtocol implements Closeable {

  static final byte TYPE_INIT = (byte) 0x80;

  static final byte CTAPHID_PING = TYPE_INIT | 0x01;
  static final byte CTAPHID_MSG = TYPE_INIT | 0x03;
  static final byte CTAPHID_LOCK = TYPE_INIT | 0x04;
  static final byte CTAPHID_INIT = TYPE_INIT | 0x06;
  static final byte CTAPHID_WINK = TYPE_INIT | 0x08;
  static final byte CTAPHID_CBOR = TYPE_INIT | 0x10;
  static final byte CTAPHID_CANCEL = TYPE_INIT | 0x11;

  static final byte CTAPHID_ERROR = TYPE_INIT | 0x3f;
  static final byte CTAPHID_KEEPALIVE = TYPE_INIT | 0x3b;

  /**
   * Protocol capabilities
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#usb-hid-init">CTAPHID_INIT</a>
   */
  public static class Capability {
    public static final byte WINK = 0x01;
    public static final byte CBOR = 0x04;
    public static final byte NMSG = 0x08;
  }

  private final CommandState defaultState = new CommandState();

  private final FidoConnection connection;

  private final Version version;
  private final int capabilities;
  private int channelId;

  private static final Logger logger = LoggerFactory.getLogger(FidoProtocol.class);

  /** The length of a message is a 16-bit field. */
  private static final int MAX_MESSAGE_LENGTH = 0xFFFF;

  /**
   * Continuation packets are numbered from 0 in seven bits, which ends a message at 128 of them,
   * 7,609 bytes. An authenticator that sends a longer message wraps the number to 0 after 127, so
   * both directions count modulo 128.
   */
  private static final int SEQUENCE_MASK = 0x7f;

  public FidoProtocol(FidoConnection connection) throws IOException {
    this.connection = connection;

    // init
    byte[] nonce = RandomUtils.getRandomBytes(8);

    channelId = 0xffffffff;
    ByteBuffer buffer = ByteBuffer.wrap(sendAndReceive(CTAPHID_INIT, nonce, null));
    byte[] responseNonce = new byte[nonce.length];
    buffer.get(responseNonce);
    if (!MessageDigest.isEqual(nonce, responseNonce)) {
      throw new IOException("Got wrong nonce!");
    }

    channelId = buffer.getInt();
    buffer.get(); // U2F HID version
    byte[] versionBytes = new byte[3];
    buffer.get(versionBytes);
    version = Version.fromBytes(versionBytes);
    capabilities = buffer.get();
    logger.debug("FIDO connection set up with channel ID: {}", String.format("0x%08x", channelId));
  }

  public byte[] sendAndReceive(byte cmd, byte[] payload, @Nullable CommandState state)
      throws IOException {
    state = state != null ? state : defaultState;

    if (payload.length > MAX_MESSAGE_LENGTH) {
      throw new IllegalArgumentException(
          String.format(
              "Payload of %d bytes does not fit in a CTAPHID message (maximum %d)",
              payload.length, MAX_MESSAGE_LENGTH));
    }

    ByteBuffer toSend = ByteBuffer.wrap(payload);
    byte[] buffer = new byte[FidoConnection.PACKET_SIZE];
    ByteBuffer packet = ByteBuffer.wrap(buffer);
    int seq = 0;

    // Send request
    packet.putInt(channelId).put(cmd).putShort((short) toSend.remaining());
    do {
      toSend.get(buffer, packet.position(), Math.min(toSend.remaining(), packet.remaining()));
      connection.send(buffer);
      if (logger.isTraceEnabled()) {
        logger.trace("{} bytes sent over fido: {}", buffer.length, StringUtils.bytesToHex(buffer));
      }
      Arrays.fill(buffer, (byte) 0);
      packet.clear();
      packet.putInt(channelId).put((byte) (seq++ & SEQUENCE_MASK));
    } while (toSend.hasRemaining());

    // Read response
    seq = 0;
    ByteBuffer response = null;
    do {
      packet.clear();
      if (state.waitForCancel(0)) {
        logger.debug("sending CTAP cancel...");
        Arrays.fill(buffer, (byte) 0);
        packet.putInt(channelId).put(CTAPHID_CANCEL);
        connection.send(buffer);
        if (logger.isTraceEnabled()) {
          logger.trace("Sent over fido: {}", StringUtils.bytesToHex(buffer));
        }
        packet.clear();
      }

      connection.receive(buffer);
      if (logger.isTraceEnabled()) {
        logger.trace("Received over fido: {}", StringUtils.bytesToHex(buffer));
      }
      int responseChannel = packet.getInt();
      if (responseChannel != channelId) {
        throw new IOException(
            String.format("Wrong Channel ID. Expecting: %d, Got: %d", channelId, responseChannel));
      }
      if (response == null) {
        byte responseCmd = packet.get();
        if (responseCmd == cmd) {
          response = ByteBuffer.allocate(packet.getShort() & 0xFFFF);
        } else if (responseCmd == CTAPHID_KEEPALIVE) {
          state.onKeepAliveStatus(packet.get());
          continue;
        } else if (responseCmd == CTAPHID_ERROR) {
          throw new IOException(String.format("CTAPHID error: %02x", packet.get()));
        } else {
          throw new IOException(
              String.format("Wrong response command. Expecting: %x, Got: %x", cmd, responseCmd));
        }
      } else {
        int responseSeq = packet.get() & 0xFF;
        int expectedSeq = seq++ & SEQUENCE_MASK;
        if (responseSeq != expectedSeq) {
          throw new IOException(
              String.format(
                  "Wrong sequence number. Expecting %d, Got: %d", expectedSeq, responseSeq));
        }
      }
      response.put(buffer, packet.position(), Math.min(packet.remaining(), response.remaining()));
    } while (response == null || response.hasRemaining());

    return response.array();
  }

  public Version getVersion() {
    return version;
  }

  public boolean supports(int capability) {
    return (capabilities & capability) == capability;
  }

  @Override
  public void close() throws IOException {
    connection.close();
    logger.debug("fido connection closed");
  }
}

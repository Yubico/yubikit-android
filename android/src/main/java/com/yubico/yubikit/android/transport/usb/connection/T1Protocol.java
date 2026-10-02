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

import com.yubico.yubikit.core.util.ZeroingByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Locale;

/**
 * Host-side ISO 7816-3 T=1 exchange for CCID readers that only offer the TPDU exchange level. Such
 * a reader passes blocks through untouched, so the host has to do the framing the reader would
 * otherwise do for it.
 *
 * <p>Chains in both directions. A command longer than the card's IFSC goes out as several I-blocks
 * with the M-bit set, each acknowledged by an R-block; a response arrives the same way and is
 * reassembled here. Without the outbound half a full-size short APDU - 261 bytes with Lc = 255 -
 * would not fit the 254-byte ceiling on a single block.
 *
 * <p>Instances are stateful: they carry N(S) and the currently agreed IFSC across calls, so one
 * instance belongs to one connection.
 */
final class T1Protocol {

  /**
   * How many blocks either side may send within a single command/response before we give up. A card
   * that keeps setting the M-bit, or keeps asking for a waiting-time extension, would otherwise
   * spin here forever; 256 is far above any real exchange (254 INF bytes each, so ~64 KiB) and
   * still terminates.
   */
  private static final int MAX_BLOCKS_PER_RESPONSE = 256;

  /** Sends one T=1 block to the card and returns the block it answered with. */
  interface BlockTransport {
    byte[] exchange(byte[] block) throws IOException;
  }

  private final BlockTransport transport;

  /**
   * The largest INF the card will accept in one block. Starts at the IFSC from the ATR and follows
   * any S(IFS) renegotiation the card asks for afterwards.
   */
  private int informationFieldSize;

  /**
   * N(S) for the next block we send. Toggles per I-block, which within a chain means per chunk
   * rather than per command (§11.6.2.2).
   */
  private int sequenceNumber = 0;

  T1Protocol(BlockTransport transport, int informationFieldSize) {
    this.transport = transport;
    this.informationFieldSize = clampInformationFieldSize(informationFieldSize);
  }

  /**
   * Send one command APDU and return the response APDU, chaining in both directions as needed.
   *
   * @throws IOException if the card sends a block we cannot act on, refuses to acknowledge a chunk
   *     of the command, or never terminates the response
   */
  byte[] sendApdu(byte[] apdu) throws IOException {
    return readResponse(sendCommand(apdu));
  }

  /**
   * Push the command out as one or more I-blocks and return the card's answer to the last of them,
   * which is where the response begins.
   */
  private byte[] sendCommand(byte[] apdu) throws IOException {
    int offset = 0;
    while (true) {
      int length = Math.min(informationFieldSize, apdu.length - offset);
      boolean moreFollows = offset + length < apdu.length;
      byte[] chunk = Arrays.copyOfRange(apdu, offset, offset + length);

      byte[] reply =
          transport.exchange(T1Block.iBlock(sequenceNumber, chunk, moreFollows).toBytes());
      sequenceNumber ^= 0x01;
      offset += length;

      if (!moreFollows) {
        return reply;
      }

      // Every chunk but the last has to be acknowledged before the next
      // one goes out; sending on regardless would leave the card
      // assembling a command out of blocks it never agreed to receive.
      T1Block acknowledgement = serviceSBlockRequests(reply);
      if (!acknowledgement.isRBlock() || acknowledgement.rBlockError() != 0) {
        throw new IOException(
            "T=1 command chunk not acknowledged: PCB=0x" + hex(acknowledgement.pcb));
      }
      if (acknowledgement.expectedSequenceNumber() != sequenceNumber) {
        throw new IOException(
            "T=1 chain acknowledgement expects N(S)="
                + acknowledgement.expectedSequenceNumber()
                + " but the next block is N(S)="
                + sequenceNumber);
      }
    }
  }

  /** Reassemble the response APDU out of the card's I-blocks, starting from {@code reply}. */
  private byte[] readResponse(byte[] reply) throws IOException {
    try (ZeroingByteArrayOutputStream payload = new ZeroingByteArrayOutputStream()) {
      for (int block = 0; block < MAX_BLOCKS_PER_RESPONSE; block++) {
        T1Block received = serviceSBlockRequests(reply);

        if (!received.isIBlock()) {
          throw new IOException(unexpectedBlockMessage(received));
        }

        payload.write(received.inf, 0, received.inf.length);
        if (!received.moreFollows()) {
          return payload.toByteArray();
        }
        // Acknowledge, naming the sequence number we expect next.
        reply = transport.exchange(T1Block.rBlock(1 - received.sequenceNumber()).toBytes());
      }
      throw new IOException(
          "T=1 response did not terminate within " + MAX_BLOCKS_PER_RESPONSE + " blocks");
    }
  }

  /**
   * Answer any S-block requests the card interleaves and return the first block that is not one.
   *
   * <p>Both requests we honour are answered by echoing the INF back with the response bit set:
   * agreeing to the proposed IFS, or granting the requested waiting-time extension.
   */
  private T1Block serviceSBlockRequests(byte[] reply) throws IOException {
    for (int block = 0; block < MAX_BLOCKS_PER_RESPONSE; block++) {
      T1Block received = T1Block.parse(reply);
      if (!received.isSBlock() || !received.isSBlockRequest()) {
        return received;
      }

      int control = received.sBlockControl();
      if (control != T1Block.S_CONTROL_IFS && control != T1Block.S_CONTROL_WTX) {
        throw new IOException(unexpectedBlockMessage(received));
      }
      if (control == T1Block.S_CONTROL_IFS && received.inf.length == 1) {
        // Agreeing to an IFS we then ignore would put the card back in
        // the position the renegotiation was meant to get it out of.
        informationFieldSize = clampInformationFieldSize(received.inf[0] & 0xFF);
      }
      reply =
          transport.exchange(T1Block.sBlock(received.sBlockResponsePcb(), received.inf).toBytes());
    }
    throw new IOException(
        "T=1 exchange made no progress within " + MAX_BLOCKS_PER_RESPONSE + " S-blocks");
  }

  /**
   * Keep the chunk size inside what a block can express. An IFSC of 0 would make no progress, and
   * 0xFF is reserved (§11.3.2.3), so both fall back to the 254-byte ceiling.
   */
  private static int clampInformationFieldSize(int ifsc) {
    return ifsc >= 1 && ifsc <= T1Block.MAX_INF_LENGTH ? ifsc : T1Block.MAX_INF_LENGTH;
  }

  private static String unexpectedBlockMessage(T1Block block) {
    String kind;
    if (block.isRBlock()) {
      // The command was fully sent and acknowledged, so a clean R-block
      // has nothing left to acknowledge, and one with an error bit set
      // is asking for a retransmission we do not attempt.
      kind = "T=1 R-block from card during response read";
    } else if (block.isSBlock()) {
      kind = "Unhandled T=1 S-block from card";
    } else {
      kind = "Unparseable T=1 block";
    }
    return kind + ": PCB=0x" + hex(block.pcb);
  }

  private static String hex(byte value) {
    return String.format(Locale.ROOT, "%02X", value);
  }
}

/*
 * Copyright (C) 2024-2026 Yubico.
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

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.util.ZeroingByteArrayOutputStream;
import java.io.IOException;

/**
 * Reassembles a response that the card delivers in several pieces. While the card answers with SW1
 * = {@code 61} (more data available), the data is collected and the next piece is requested with
 * GET RESPONSE or the application's own "send remaining" instruction.
 *
 * <p>ISO/IEC 7816-4 puts no limit on such a chain, so a card that never ends it would keep the host
 * reading and collecting data forever. The chain is therefore bounded, and a card that goes past
 * either bound is reported with a {@link BadResponseException}:
 *
 * <ul>
 *   <li>The collected data is at most {@value #MAX_RESPONSE_LENGTH} bytes. That is far above what
 *       any YubiKey application returns, which is a few kilobytes, and only protects memory.
 *   <li>At most {@value #MAX_EMPTY_ROUNDS} pieces in a row carry no data. One empty piece is
 *       normal, the first answer of a card that only announces how much it has to send. A card that
 *       keeps answering without delivering anything is not making progress.
 * </ul>
 */
class ChainedResponseProcessor implements ApduProcessor {
  private static final byte SW1_HAS_MORE_DATA = 0x61;

  /** The most response data collected from one chain, in bytes. */
  static final int MAX_RESPONSE_LENGTH = 1024 * 1024;

  /** The most pieces in a row of a chain that may carry no data. */
  static final int MAX_EMPTY_ROUNDS = 16;

  protected final ApduProcessor delegate;
  private final Apdu getData;

  ChainedResponseProcessor(ApduProcessor delegate, byte insSendRemaining) {
    this.delegate = delegate;
    getData = new Apdu((byte) 0, insSendRemaining, (byte) 0, (byte) 0, new byte[0], 0);
  }

  @Override
  public ApduResponse sendApdu(Apdu apdu) throws IOException, BadResponseException {
    ApduResponse response = delegate.sendApdu(apdu);
    // Read full response
    try (ZeroingByteArrayOutputStream readBuffer = new ZeroingByteArrayOutputStream()) {
      int emptyRounds = 0;
      while (response.getSw() >> 8 == SW1_HAS_MORE_DATA) {
        byte[] data = response.getData();
        if (data.length == 0) {
          if (++emptyRounds > MAX_EMPTY_ROUNDS) {
            throw new BadResponseException(
                "Response chain made no progress within " + MAX_EMPTY_ROUNDS + " pieces");
          }
        } else {
          emptyRounds = 0;
        }
        append(readBuffer, data);
        response = delegate.sendApdu(getData);
      }
      append(readBuffer, response.getData());
      readBuffer.write(response.getSw() >> 8);
      readBuffer.write(response.getSw() & 0xff);
      return new ApduResponse(readBuffer.toByteArray());
    }
  }

  private static void append(ZeroingByteArrayOutputStream buffer, byte[] data)
      throws BadResponseException {
    if (buffer.size() + data.length > MAX_RESPONSE_LENGTH) {
      throw new BadResponseException("Response chain exceeds " + MAX_RESPONSE_LENGTH + " bytes");
    }
    buffer.write(data, 0, data.length);
  }
}

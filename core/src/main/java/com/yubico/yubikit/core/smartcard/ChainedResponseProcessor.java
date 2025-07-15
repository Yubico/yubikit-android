/*
 * Copyright (C) 2024-2025 Yubico.
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
import java.io.ByteArrayOutputStream;
import java.io.IOException;

class ChainedResponseProcessor implements ApduProcessor {
  private static final byte SW1_HAS_MORE_DATA = 0x61;

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
    ByteArrayOutputStream readBuffer = new ByteArrayOutputStream();
    while (response.getSw() >> 8 == SW1_HAS_MORE_DATA) {
      readBuffer.write(response.getData());
      response = delegate.sendApdu(getData);
    }
    readBuffer.write(response.getData());
    readBuffer.write(response.getSw() >> 8);
    readBuffer.write(response.getSw() & 0xff);
    return new ApduResponse(readBuffer.toByteArray());
  }
}

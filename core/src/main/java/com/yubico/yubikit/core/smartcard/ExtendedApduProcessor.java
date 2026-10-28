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

import java.io.IOException;

/**
 * Sends APDUs as extended length APDUs, and falls back to command chaining with short APDUs for
 * data which does not fit in a single extended length APDU. A YubiKey may accept larger objects
 * than fit in one APDU.
 */
class ExtendedApduProcessor implements ApduProcessor {
  private final ExtendedApduFormatter formatter;
  private final ApduFormatProcessor extended;
  private final CommandChainingProcessor chaining;

  ExtendedApduProcessor(SmartCardConnection connection, ExtendedApduFormatter formatter) {
    this.formatter = formatter;
    this.extended = new ApduFormatProcessor(connection, formatter);
    this.chaining = new CommandChainingProcessor(connection, new ShortApduFormatter());
  }

  @Override
  public ApduResponse sendApdu(Apdu apdu) throws IOException {
    int length = apdu.getData().length;
    if (length > ShortApduFormatter.SHORT_APDU_MAX_CHUNK && !formatter.fits(length, apdu.getLe())) {
      return chaining.sendApdu(withShortLe(apdu));
    }
    return extended.sendApdu(apdu);
  }

  /** An Le beyond what a short APDU can express is left out, the rest is fetched by chaining. */
  private static Apdu withShortLe(Apdu apdu) {
    if (apdu.getLe() <= ShortApduFormatter.SHORT_APDU_MAX_CHUNK) {
      return apdu;
    }
    return new Apdu(apdu.getCla(), apdu.getIns(), apdu.getP1(), apdu.getP2(), apdu.getData(), 0);
  }
}

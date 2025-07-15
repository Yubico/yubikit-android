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
import java.io.IOException;

class TouchWorkaroundProcessor implements ApduProcessor {
  private final ApduProcessor delegate;
  private long lastLongResponse = 0;

  TouchWorkaroundProcessor(ApduProcessor delegate) {
    this.delegate = delegate;
  }

  @Override
  public ApduResponse sendApdu(Apdu apdu) throws IOException, BadResponseException {
    if (lastLongResponse > 0 && System.currentTimeMillis() - lastLongResponse < 2000) {
      delegate.sendApdu(new Apdu(0, 0, 0, 0, null)); // Dummy APDU; returns an error
      lastLongResponse = 0;
    }
    ApduResponse response = delegate.sendApdu(apdu);

    if (response.getBytes().length > 54) {
      lastLongResponse = System.currentTimeMillis();
    } else {
      lastLongResponse = 0;
    }

    return response;
  }
}

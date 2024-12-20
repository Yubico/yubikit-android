/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.testing.fido.utils;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Config;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.testing.fido.FidoTestState;
import java.io.IOException;

public class ConfigHelper {
  public static Config getConfig(Ctap2Session session, FidoTestState state)
      throws IOException, CommandException {
    ClientPin clientPin = new ClientPin(session, state.getPinUvAuthProtocol());
    byte[] pinToken = clientPin.getPinToken(TestData.PIN, ClientPin.PIN_PERMISSION_ACFG, null);
    return new Config(session, state.getPinUvAuthProtocol(), pinToken);
  }
}

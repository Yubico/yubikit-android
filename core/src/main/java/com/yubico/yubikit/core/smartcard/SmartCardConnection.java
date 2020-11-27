/*
 * Copyright (C) 2019 Yubico.
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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyConnection;

import java.io.IOException;

/**
 * A connection capable of sending APDUs and receiving their responses.
 */
public interface SmartCardConnection extends YubiKeyConnection {
    /**
     * Sends a command APDU to the YubiKey, and reads a response.
     *
     * @param apdu The binary APDU data to be sent.
     * @return The response back from the YubiKey.
     * @throws IOException in case of communication error
     */
    byte[] sendAndReceive(byte[] apdu) throws IOException;

    /**
     * Checks what transport the connection is using (USB or NFC).
     *
     * @return the physical transport used for the connection.
     */
    Transport getTransport();
}
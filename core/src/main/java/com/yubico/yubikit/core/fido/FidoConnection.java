/*
 * Copyright (C) 2020 Yubico.
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

import com.yubico.yubikit.core.YubiKeyConnection;

import java.io.IOException;

/**
 * A HID CTAP connection to a YubiKey.
 */
public interface FidoConnection extends YubiKeyConnection {
    int PACKET_SIZE = 64;

    /**
     * Sends a HID CTAP packet to the YubiKey.
     */
    void send(byte[] packet) throws IOException;

    /**
     * Receives a HID CTAP packet from the YubiKey.
     */
    void receive(byte[] packet) throws IOException;
}

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

package com.yubico.yubikit.iso7816;

import com.yubico.yubikit.utils.Interface;

import java.io.Closeable;
import java.io.IOException;

/**
 * Defines the interface for execution of raw Apdu commands
 */
public interface Iso7816Connection extends Closeable {
    /**
     * Synchronously send a command APDU to the YubiKey, and reads a response.
     *
     * @param apdu The binary APDU data to be sent.
     * @return The response back from the YubiKey.
     * @throws IOException in case of communication error
     */
    byte[] transceive(byte[] apdu) throws IOException;

    /**
     * Retrieve Answer to reset (or answer to select for NFC)
     *
     * @return data block returned for reset command
     */
    byte[] getAtr();

    /**
     * Checks what interface the connection is using (USB or NFC).
     *
     * @return the physical interface used for the connection.
     */
    Interface getInterface();
}
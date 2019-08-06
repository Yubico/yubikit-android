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

package com.yubico.yubikit.transport;

import com.yubico.yubikit.apdu.Apdu;
import com.yubico.yubikit.apdu.ApduResponse;
import com.yubico.yubikit.exceptions.YubikeyCommunicationException;

import java.io.Closeable;
import java.io.IOException;

/**
 * Defines the interface for execution of raw Apdu commands
 */
public interface Iso7816Connection extends Closeable {

    /**
     * Sets connection/communication timeout in milliseconds
     *
     * @param timeoutMs connection timeout in ms
     */
    void setTimeout(int timeoutMs);

    /**
     * Closes the communication with the key and disables the key connection events. After calling this method the session will
     * be closed asynchronously and the application will receive events on the sessionState when the session is closed.
     *
     * @throws IOException if failed to close connection
     */
    @Override
    void close() throws IOException;

    /**
     * Sends synchronously to the key a raw APDU command to be executed.
     * Calling this method will block the execution of the calling thread until the request is fulfilled by the key or if it's timing out.
     * <p>
     * This method should never be called from the main thread.
     *
     * @param command The APDU command to be executed.
     * @return The response block which is executed after the request was processed by the key.
     * @throws IOException in case of communication error
     */
    ApduResponse execute(Apdu command) throws IOException;

    /**
     * Retrieve Answer to reset (or answer to select for NFC)
     * @return data block returned for reset command
     * @throws IOException in case of communication error
     */
    byte[] getAtr() throws IOException;
}
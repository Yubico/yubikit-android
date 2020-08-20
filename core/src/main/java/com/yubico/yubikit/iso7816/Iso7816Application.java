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

import com.yubico.yubikit.exceptions.ApplicationNotAvailableException;

import java.io.Closeable;
import java.io.IOException;
import java.util.Arrays;

/**
 * Class that allows to open ISO 7816 connection to YubiKey
 * and communicate using APDUs
 */
public class Iso7816Application implements Closeable {
    private static final byte INS_SELECT = (byte) 0xa4;
    private static final byte P1_SELECT = (byte) 0x04;
    private static final byte P2_SELECT = (byte) 0x00;

    private static final short SW_FILE_NOT_FOUND = 0x6a82;

    /**
     * Application Identified used when selecting the application.
     */
    private final byte[] aid;

    /**
     * Open ISO 7816 connection to yubikey
     */
    private Iso7816Connection connection;

    /**
     * Create new instance of {@link Iso7816Application}
     * and selects the application for use
     *
     * @param aid        the AID of the application
     * @param connection connection to the YubiKey
     */
    public Iso7816Application(byte[] aid, Iso7816Connection connection) {
        this.connection = connection;
        this.aid = Arrays.copyOf(aid, aid.length);
    }


    @Override
    public void close() throws IOException {
        connection.close();
    }

    /**
     * @return open ISO 7816 connection to yubikey
     */
    public Iso7816Connection getConnection() {
        return connection;
    }

    /**
     * Answer to reset
     *
     * @return response to identify card reader
     */
    public byte[] getAtr() {
        return connection.getAtr();
    }

    public byte[] getAid() {
        return aid;
    }

    /**
     * Sends APDU command and receives byte array from connection
     * In case if length of output blob is bigger than 255 than it splits into set of APDU commands
     * In case if output has status code that it has remaining info sends another APDU command to receive what's remaining
     *
     * @param command well structured command that needs to be send
     * @return data blob concatenated from all APDU commands that were sent *set of output commands and send remaining commands)
     * @throws IOException   in case of connection and communication error
     * @throws ApduException in case if received error in APDU response
     */
    public byte[] sendAndReceive(Apdu command) throws IOException, ApduException {
        return ApduUtils.sendAndReceive(connection, command);
    }

    /**
     * Sends an APDU to SELECT the Application.
     *
     * @return the response data from selecting the Application
     * @throws IOException   in case of connection or communication error
     * @throws ApplicationNotAvailableException in case the AID doesn't match an available application
     */
    public byte[] select() throws IOException, ApplicationNotAvailableException {
        try {
            return sendAndReceive(new Apdu(0, INS_SELECT, P1_SELECT, P2_SELECT, aid));
        } catch (ApduException e) {
            if (e.getStatusCode() == SW_FILE_NOT_FOUND) {
                throw new ApplicationNotAvailableException("The application couldn't be selected", e);
            }
            throw new IOException("Unexpected SW", e);
        }
    }
}

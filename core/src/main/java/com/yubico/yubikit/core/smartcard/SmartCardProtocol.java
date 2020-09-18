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

import com.yubico.yubikit.core.ApplicationNotAvailableException;
import com.yubico.yubikit.core.Interface;
import com.yubico.yubikit.core.Version;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Class that allows to open ISO 7816 connection to YubiKey
 * and communicate using APDUs
 */
public class SmartCardProtocol implements Closeable {
    private static final byte INS_SELECT = (byte) 0xa4;
    private static final byte P1_SELECT = (byte) 0x04;
    private static final byte P2_SELECT = (byte) 0x00;
    private static final byte INS_SEND_REMAINING = (byte) 0xc0;

    private static final short SW_SUCCESS = (short) 0x9000;
    private static final short SW_FILE_NOT_FOUND = 0x6a82;
    private static final byte SW1_HAS_MORE_DATA = 0x61;

    private static final int SHORT_APDU_MAX_CHUNK = 0xff;

    /**
     * Application Identified used when selecting the application.
     */
    private final byte[] aid;

    private final byte insSendRemaining;

    /**
     * Open ISO 7816 connection to yubikey
     */
    private final SmartCardConnection connection;

    private boolean useTouchWorkaround = false;
    private long lastLongResponse = 0;

    /**
     * Create new instance of {@link SmartCardProtocol}
     * and selects the application for use
     *
     * @param aid        the AID of the application
     * @param connection connection to the YubiKey
     */
    public SmartCardProtocol(byte[] aid, SmartCardConnection connection) {
        this(aid, connection, INS_SEND_REMAINING);
    }

    public SmartCardProtocol(byte[] aid, SmartCardConnection connection, byte insSendRemaining) {
        this.connection = connection;
        this.aid = Arrays.copyOf(aid, aid.length);
        this.insSendRemaining = insSendRemaining;
    }

    @Override
    public void close() throws IOException {
        connection.close();
    }

    /**
     * YubiKey 4.2.0 - 4.2.6 have an issue with the touch timeout being too short in certain cases. Enable this workaround
     * on such devices to trigger sending a dummy command which mitigates the issue.
     *
     * @param firmwareVersion the firmware version to use for detection to enable the workaround
     */
    public void enableTouchWorkaround(Version firmwareVersion) {
        this.useTouchWorkaround = connection.getInterface() == Interface.USB
                && firmwareVersion.isAtLeast(4, 2, 0)
                && firmwareVersion.isLessThan(4, 2, 7);
    }

    /**
     * @return open ISO 7816 connection to yubikey
     */
    public SmartCardConnection getConnection() {
        return connection;
    }

    public byte[] getAid() {
        return Arrays.copyOf(aid, aid.length);
    }

    /**
     * Sends an APDU to SELECT the Application.
     *
     * @return the response data from selecting the Application
     * @throws IOException                      in case of connection or communication error
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

    /**
     * Sends APDU command and receives byte array from connection
     * In case if output has status code that it has remaining info sends another APDU command to receive what's remaining
     *
     * @param command well structured command that needs to be send
     * @return data blob concatenated from all APDU commands that were sent *set of output commands and send remaining commands)
     * @throws IOException   in case of connection and communication error
     * @throws ApduException in case if received error in APDU response
     */
    public byte[] sendAndReceive(Apdu command) throws IOException, ApduException {
        if (useTouchWorkaround && lastLongResponse > 0 && System.currentTimeMillis() - lastLongResponse < 2000) {
            connection.sendAndReceive(new byte[5]);  // Dummy APDU; returns an error
            lastLongResponse = 0;
        }
        ApduResponse response = new ApduResponse(connection.sendAndReceive(encodeExtended(command)));

        // Read full response
        ByteArrayOutputStream readBuffer = new ByteArrayOutputStream();
        byte[] getData = new byte[]{0x00, insSendRemaining, 0x00, 0x00};
        while (response.getSw() >> 8 == SW1_HAS_MORE_DATA) {
            readBuffer.write(response.getData());
            response = new ApduResponse(connection.sendAndReceive(getData));
        }

        if (response.getSw() != SW_SUCCESS) {
            throw new ApduException(response);
        }
        readBuffer.write(response.getData());
        byte[] responseData = readBuffer.toByteArray();

        if (useTouchWorkaround && responseData.length > 54) {
            lastLongResponse = System.currentTimeMillis();
        } else {
            lastLongResponse = 0;
        }
        return responseData;
    }

    private static byte[] encodeShort(byte cla, Apdu command, int length) {
        if (length > SHORT_APDU_MAX_CHUNK) {
            throw new IllegalArgumentException("Length must be no greater than " + SHORT_APDU_MAX_CHUNK);
        }
        byte[] header = new byte[]{cla, command.getIns(), command.getP1(), command.getP2()};
        if (length == 0) {
            return header;
        }
        return ByteBuffer.allocate(header.length + 1 + length)
                .put(header)
                .put((byte) length)
                .put(command.getData(), 0, length)
                .array();
    }

    private static byte[] encodeExtended(Apdu command) {
        int dataLen = command.getData().length;
        if (dataLen <= SHORT_APDU_MAX_CHUNK) {
            return encodeShort(command.getCla(), command, dataLen);
        }
        return ByteBuffer.allocate(4 + 3 + dataLen)
                .put(command.getCla())
                .put(command.getIns())
                .put(command.getP1())
                .put(command.getP2())
                .put((byte) 0x00)
                .putShort((short) dataLen)
                .put(command.getData())
                .array();
    }
}

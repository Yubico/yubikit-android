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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Methods that allow to send APDU commands and handle input and output that doesn't fit into 1 APDU blob
 */
public class ApduUtils {
    /**
     * Smart Card Error Codes
     * Code	Description
     * General Error Codes
     * 6400	No specific diagnosis
     * 6700	Wrong length in Lc
     * 6982	Security status not satisfied
     * 6985	Conditions of use not satisfied
     * 6a86	Incorrect P1 P2
     * 6d00	Invalid instruction
     * 6e00	Invalid class
     * Install Load Errors
     * 6581	Memory Failure
     * 6a80	Incorrect parameters in data field
     * 6a84	Not enough memory space
     * 6a88	Referenced data not found
     * Delete Errors
     * 6200	Application has been logically deleted
     * 6581	Memory failure
     * 6985	Referenced data cannot be deleted
     * 6a88	Referenced data not found
     * 6a82	Application not found
     * 6a80	Incorrect values in command data
     * Get Data Errors
     * 6a88	Referenced data not found
     * Get Status Errors
     * 6310	More data available
     * 6a88	Referenced data not found
     * 6a80	Incorrect values in command data
     * Load Errors
     * 6581	Memory failure
     * 6a84	Not enough memory space
     * 6a86	Incorrect P1/P2
     * 6985	Conditions of use not satisfied
     */
    private static final short SW_SUCCESS = (short) 0x9000;
    private static final byte SW1_HAS_MORE_DATA = 0x61;

    private static final int SHORT_APDU_MAX_CHUNK = 0xff;
    private static final byte INS_SEND_REMAINING = (byte) 0xc0;


    /**
     * Sends APDU command and receives byte array from connection
     * In case if output has status code that it has remaining info sends another APDU command to receive what's remaining
     *
     * @param connection iso 7816 connection to yubikey
     * @param command    well structured command that needs to be send
     * @return data blob concatenated from all APDU commands that were sent *set of output commands and send remaining commands)
     * @throws IOException   in case of connection and communication error
     * @throws ApduException in case if received error in APDU response
     */
    public static byte[] sendAndReceive(Iso7816Connection connection, Apdu command) throws IOException, ApduException {
        return sendAndReceive(connection, command, INS_SEND_REMAINING);
    }

    /**
     * Sends APDU command and receives byte array from connection
     * In case if output has status code that it has remaining info sends another APDU command to receive what's remaining
     *
     * @param connection       iso 7816 connection to yubikey
     * @param command          well structured command that needs to be send
     * @param insSentRemaining instruction byte for APDU command to receive remaining data blob (default is 0xc0)
     * @return data blob concatenated from all APDU commands that were sent *set of output commands and send remaining commands)
     * @throws IOException   in case of connection and communication error
     * @throws ApduException in case if received error in APDU response
     */
    public static byte[] sendAndReceive(Iso7816Connection connection, Apdu command, byte insSentRemaining) throws IOException, ApduException {
        ApduResponse response = new ApduResponse(connection.transceive(encodeExtended(command)));

        // Read full response
        ByteArrayOutputStream readBuffer = new ByteArrayOutputStream();
        byte[] getData = new byte[]{0x00, insSentRemaining, 0x00, 0x00};
        while (response.getSw() >> 8 == SW1_HAS_MORE_DATA) {
            readBuffer.write(response.getData());
            response = new ApduResponse(connection.transceive(getData));
        }

        if (response.getSw() != SW_SUCCESS) {
            throw new ApduException(response);
        }
        readBuffer.write(response.getData());
        return readBuffer.toByteArray();
    }

    private static byte[] encodeShort(byte cla, Apdu command, int offset, int length) {
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
                .put(command.getData(), offset, length)
                .array();
    }

    private static byte[] encodeExtended(Apdu command) {
        int dataLen = command.getData().length;
        if (dataLen <= SHORT_APDU_MAX_CHUNK) {
            return encodeShort(command.getCla(), command, 0, dataLen);
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

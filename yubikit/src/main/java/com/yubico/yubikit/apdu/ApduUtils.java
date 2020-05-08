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

package com.yubico.yubikit.apdu;

import com.yubico.yubikit.exceptions.ApduException;
import com.yubico.yubikit.transport.Iso7816Connection;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Methods that allow to send APDU commands and handle input and output that doesn't fit into 1 APDU blob
 */
public class ApduUtils {
    /**
     Smart Card Error Codes
     Code	Description
     General Error Codes
     6400	No specific diagnosis
     6700	Wrong length in Lc
     6982	Security status not satisfied
     6985	Conditions of use not satisfied
     6a86	Incorrect P1 P2
     6d00	Invalid instruction
     6e00	Invalid class
     Install Load Errors
     6581	Memory Failure
     6a80	Incorrect parameters in data field
     6a84	Not enough memory space
     6a88	Referenced data not found
     Delete Errors
     6200	Application has been logically deleted
     6581	Memory failure
     6985	Referenced data cannot be deleted
     6a88	Referenced data not found
     6a82	Application not found
     6a80	Incorrect values in command data
     Get Data Errors
     6a88	Referenced data not found
     Get Status Errors
     6310	More data available
     6a88	Referenced data not found
     6a80	Incorrect values in command data
     Load Errors
     6581	Memory failure
     6a84	Not enough memory space
     6a86	Incorrect P1/P2
     6985	Conditions of use not satisfied
     */
    private static final short SW_SUCCESS = (short)0x9000;
    private static final byte SW1_HAS_MORE_DATA = 0x61;

    private static final int MAX_CHUNK = 0xff;
    private static final byte INS_SEND_REMAINING = (byte) 0xc0;


    /**
     * Sends APDU command and receives byte array from connection
     * In case if length of output blob is bigger than 255 than it splits into set of APDU commands
     * In case if output has status code that it has remaining info sends another APDU command to receive what's remaining
     * @param connection iso 7816 connection to yubikey
     * @param command well structured command that needs to be send
     * @return data blob concatenated from all APDU commands that were sent *set of output commands and send remaining commands)
     * @throws IOException in case of connection and communication error
     * @throws ApduException in case if received error in APDU response
     */
    public static byte[] sendAndReceive(Iso7816Connection connection, Apdu command) throws IOException, ApduException {
        return sendAndReceive(connection, command, INS_SEND_REMAINING);
    }

    /**
     * Sends APDU command and receives byte array from connection
     * In case if length of output blob is bigger than 255 than it splits into set of APDU commands
     * In case if output has status code that it has remaining info sends another APDU command to receive what's remaining
     * @param connection iso 7816 connection to yubikey
     * @param command well structured command that needs to be send
     * @param insSentRemaining instruction byte for APDU command to receive remaining data blob (default is 0xc0)
     * @return data blob concatenated from all APDU commands that were sent *set of output commands and send remaining commands)
     * @throws IOException in case of connection and communication error
     * @throws ApduException in case if received error in APDU response
     */
    public static byte[] sendAndReceive(Iso7816Connection connection, Apdu command, byte insSentRemaining) throws IOException, ApduException {
        List<Apdu> listCommands = splitDataInChunks(command);
        int i;
        for (i = 0; i < listCommands.size() - 1; i++) {
            Apdu apdu = listCommands.get(i);
            ApduResponse readResponse = connection.execute(apdu);
            // every time we send a chunk we should receive success code
            if (readResponse.getSw() != SW_SUCCESS) {
                throw new ApduException(readResponse);
            }
        }

        // last chunk response has data and needs to be returned
        return sendAndReceiveWithRemaining(connection, listCommands.get(i), insSentRemaining);
    }

    /**
     * Sends APDU command and receives byte array from connection
     * In case if output has status code that it has remaining info sends another APDU command to receive what's remaining
     * @param connection iso 7816 connection to yubikey
     * @param command well structured command that needs to be send
     * @param insSentRemaining instruction byte for APDU command to receive remaining data blob (default is 0xc0)
     * @return data blob concatenated from all APDU commands that were sent *set of output commands and send remaining commands)
     * @throws IOException in case of connection and communication error
     * @throws ApduException in case if received error in APDU response
     */
    private static byte[] sendAndReceiveWithRemaining(Iso7816Connection connection, Apdu command, byte insSentRemaining) throws IOException, ApduException {
        ByteArrayOutputStream readBuffer = new ByteArrayOutputStream();
        Apdu apdu = command;
        boolean sendRemaining = true;
        while (sendRemaining) {
            ApduResponse readResponse = connection.execute(apdu);
            short statusCode = readResponse.getSw();
            byte[] responseData = readResponse.getData();
            if (readResponse.getSw() == SW_SUCCESS) {
                sendRemaining = false;
            } else if (readResponse.getSw() >> 8 == SW1_HAS_MORE_DATA) {
                apdu = new Apdu(0x00, insSentRemaining, 0x00, 0x00, null, Apdu.Type.SHORT);
            } else {
                throw new ApduException(readResponse);
            }
            if (responseData!= null) {
                readBuffer.write(responseData);
            }
        }
        return readBuffer.toByteArray();
    }

    /**
     * If APDU type is SHORT than we need to split outcoming data into chunks that are not longer than 255 bytes
     * @param command APDU command with any length of data
     * @return list of APDU commands with length of data <= 255
     */
    private static List<Apdu> splitDataInChunks(Apdu command) {
        List<Apdu> list = new ArrayList<>();

        byte[] data = command.getData();
        int dataLength = data != null ? data.length : 0;
        int offset = 0;
        while (command.getType() == Apdu.Type.SHORT && (dataLength - offset) > MAX_CHUNK) {
            list.add(new Apdu(0x10, command.getIns(), command.getP1(), command.getP2(), Arrays.copyOfRange(data, offset, offset + MAX_CHUNK)));
            offset += MAX_CHUNK;
        }
        list.add(new Apdu(0x00, command.getIns(), command.getP1(), command.getP2(), data != null ? Arrays.copyOfRange(data, offset, dataLength) : null));
        return list;
    }
}

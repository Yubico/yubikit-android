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

import androidx.annotation.Nullable;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * Data model for encapsulating an APDU command, as defined by ISO/IEC 7816-4 standard.
 */
public class Apdu {

    private static int APDU_MIN_LEN = 4;
    private static int APDU_EXTENDED_MIN_LEN = 6;

    /** Raw array of command bytes that contains all command bytes (cla, ins, p1, p2), length and data bytes */
    private byte[] bytes;

    /** Class of an APDU as defined in GlobalPlatform Card Specification */
    private byte cla;

    /** Instruction of an APDU as defined in GlobalPlatform Card Specification */
    private byte ins;

    /** Parameter 1 of an APDU as defined in GlobalPlatform Card Specification */
    private byte p1;

    /** Parameter 2 of an APDU as defined in GlobalPlatform Card Specification */
    private byte p2;

    /** Command data of an APDU as defined in GlobalPlatform Card Specification */
    private byte[] data;

    /** The type of the APDU, short or extended. */
    private Type type;

    /**
     * Creates a new APDU binary command from a list of parameters specified by the ISO/IEC 7816-4 standard.
     *
     * @param cla  The instruction class.
     * @param ins  The instruction number.
     * @param p1   The first instruction parameter byte.
     * @param p2   The second instruction parameter byte.
     * @param data The command data.
     * @param type The type of the APDU, short or extended.
     */
    private Apdu(byte cla, byte ins, byte p1, byte p2, byte[] data, Type type) {
        this.cla = cla;
        this.ins = ins;
        this.p1 = p1;
        this.p2 = p2;
        this.data = data == null ? new byte[0] : data;
        this.type = type;
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(cla);
        stream.write(ins);
        stream.write(p1);
        stream.write(p2);
        if (data != null && data.length > 0) {
            if (type == Type.SHORT) {
                stream.write((byte)data.length);
                stream.write(data, 0, data.length);
            } else {
                byte lengthHigh = (byte)(data.length / 256);
                byte lengthLow = (byte)(data.length % 256);
                stream.write(lengthHigh);
                stream.write(lengthLow);
                stream.write(data, 0, data.length);
            }
        } else {
            if (type == Type.EXTENDED) {
                stream.write(0x00); // lengthHigh
                stream.write(0x00); // lengthLow
            }
        }
        bytes = stream.toByteArray();
    }

    /**
     * Creates a new APDU binary command from a list of parameters specified by the ISO/IEC 7816-4 standard.
     *
     * @param cla  The instruction class.
     * @param ins  The instruction number.
     * @param p1   The first instruction parameter byte.
     * @param p2   The second instruction parameter byte.
     * @param data The command data.
     * @param type The type of the APDU, short or extended.
     */
    public Apdu(int cla, int ins, int p1, int p2, @Nullable byte[] data, Type type) {
        this(validateByte(cla, "CLA"),
                validateByte( ins, "INS"),
                validateByte( p1, "P1"),
                validateByte( p2, "P2"),
                data,
                type);
    }

    /**
     * Creates a new APDU binary command from a list of parameters specified by the ISO/IEC 7816-4 standard.
     *
     * @param cla  The instruction class.
     * @param ins  The instruction number.
     * @param p1   The first instruction parameter byte.
     * @param p2   The second instruction parameter byte.
     * @param data The command data.
     */
    public Apdu(int cla, int ins, int p1, int p2, @Nullable byte[] data) {
        this(cla, ins, p1, p2, data, Type.SHORT);
    }

    /**
     * Creates a new APDU with pre-built data.
     * This initializer checks for the data integrity.
     * @param apduBytes The pre-built APDU data.
     */
    public Apdu(byte[] apduBytes) {
        this(apduBytes, Type.SHORT);
    }


    /**
     * Creates a new APDU with pre-built data.
     * This initializer checks for the data integrity.
     * @param apduBytes The pre-built APDU data.
     * @param type The type of the APDU, short or extended.
     */
    public Apdu(byte[] apduBytes, Type type) {
        bytes = apduBytes;
        if (apduBytes.length < APDU_MIN_LEN) {
            throw new IllegalArgumentException("apdu command should have at least 4 bytes");
        }
        int pointer = 0;
        this.cla = apduBytes[pointer++];
        this.ins = apduBytes[pointer++];
        this.p1 = apduBytes[pointer++];
        this.p2 = apduBytes[pointer++];
        this.type = type;
        if (type == Type.SHORT) {
            int length = apduBytes.length == APDU_MIN_LEN ? 0 : apduBytes[pointer];
            this.data = length != 0 ? Arrays.copyOfRange(apduBytes, 5, apduBytes.length) : null;
        } else {
            if (apduBytes.length < APDU_EXTENDED_MIN_LEN) {
                throw new IllegalArgumentException("extended apdu command should have at least 6 bytes");
            }
            int length = (apduBytes[pointer++] << 8) + apduBytes[pointer];
            this.data = length != 0 ? Arrays.copyOfRange(apduBytes, 6, apduBytes.length) : null;
        }
    }

    /**
     * Byte stream of APDU command
     * @return byte array of all APDU data (cla, ins, p1, p2, length, and data)
     */
    public byte[] getBytes() {
        return bytes;
    }

    /**
     * APDU command data
     * @return byte array of APDU data
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Type of command
     * @return SHORT or EXTENDED
     */
    public Type getType() {
        return type;
    }

    /**
     * @return Class of an APDU
     */
    public byte getCla() {
        return cla;
    }

    /**
     * @return Instruction of an APDU
     */
    public byte getIns() {
        return ins;
    }

    /**
     * @return Parameter 1 of an APDU
     */
    public byte getP1() {
        return p1;
    }

    /**
     * @return Parameter 1 of an APDU
     */
    public byte getP2() {
        return p2;
    }

    /**
     * Validates that integer passed fits into byte and converts to byte
     * @param byteInt integer that will be converted to byte
     * @param name name of parameter
     * @return
     */
    private static byte validateByte(int byteInt, String name) {
        if (byteInt > 255) {
            throw new IllegalArgumentException("Invalid value for " + name + ", must fit in a byte");
        }
        return (byte) byteInt;
    }

    /**
     * Refers to the encoding type of APDU as defined in ISO/IEC 7816-4 standard.
     */
    public enum Type {
        /**
         * Data does not exceed 256 bytes in lenght. CCID commands usually are encoded with short APDUs.
         */
        SHORT,
        /**
         * Data exceeds 256 bytes in length. Some YubiKey applications (like U2F) use extended APDUs.
         */
        EXTENDED
    }
}



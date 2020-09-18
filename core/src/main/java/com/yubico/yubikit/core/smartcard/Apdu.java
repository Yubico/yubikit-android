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

import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.annotation.Nullable;

/**
 * Data model for encapsulating an APDU command, as defined by ISO/IEC 7816-4 standard.
 */
public class Apdu {
    /* Raw array of command bytes that contains all command bytes (cla, ins, p1, p2), length and data bytes */
    private final byte cla;
    private final byte ins;
    private final byte p1;
    private final byte p2;
    private final byte[] data;


    /**
     * Creates a new APDU binary command from a list of parameters specified by the ISO/IEC 7816-4 standard.
     *
     * @param cla  The instruction class.
     * @param ins  The instruction number.
     * @param p1   The first instruction parameter byte.
     * @param p2   The second instruction parameter byte.
     * @param data The command data.
     */
    private Apdu(byte cla, byte ins, byte p1, byte p2, @Nullable byte[] data) {
        this.cla = cla;
        this.ins = ins;
        this.p1 = p1;
        this.p2 = p2;
        this.data = data == null ? new byte[0] : data;
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
        this(validateByte(cla, "CLA"),
                validateByte(ins, "INS"),
                validateByte(p1, "P1"),
                validateByte(p2, "P2"),
                data
        );
    }

    /**
     * APDU command data
     *
     * @return byte array of APDU data
     */
    public byte[] getData() {
        return Arrays.copyOf(data, data.length);
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
     * @return Parameter 2 of an APDU
     */
    public byte getP2() {
        return p2;
    }

    /*
     * Validates that integer passed fits into byte and converts to byte
     */
    private static byte validateByte(int byteInt, String name) {
        if (byteInt > 255) {
            throw new IllegalArgumentException("Invalid value for " + name + ", must fit in a byte");
        }
        return (byte) byteInt;
    }
}



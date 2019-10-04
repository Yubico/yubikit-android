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

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * Tag, length, value structure that helps to parse APDU response data
 */
public class Tlv {
    private static int LENGTH_REQUIRES_EXTRA_BYTE = 0x81;
    private static int LENGTH_REQUIRES_EXTRA_TWO_BYTES = 0x82;
    private final int tag;
    private final int length;
    private final byte[] data;
    private final int offset;

    /**
     * Creates instance of {@link Tlv}
     * @param data raw bytes that needs to be converted into Tlv
     * @param dataOffset offset within data byte array
     */
    public Tlv(byte[] data, int dataOffset) {
        int pointer = 0;
        tag = data[dataOffset + pointer++] & 0xFF;
        int checkByte = data[dataOffset + pointer++] & 0xFF;
        if (checkByte < LENGTH_REQUIRES_EXTRA_BYTE) {
            offset = 2;
            length = checkByte;
        } else if (checkByte == LENGTH_REQUIRES_EXTRA_BYTE)  {
            offset = 3;
            length = data[dataOffset + pointer] & 0xFF;
        } else if (checkByte == LENGTH_REQUIRES_EXTRA_TWO_BYTES) {
            offset = 4;
            length = ((data[dataOffset + pointer++] & 0xFF) << 8) + (data[dataOffset + pointer] & 0xFF);
        } else {
            length = 0;
            offset = 0;
        }
        this.data = Arrays.copyOfRange(data, dataOffset, dataOffset + offset + length);
    }

    /**
     * Creates instance of {@link Tlv}
     * @param tag the tag of structure
     * @param value the value of structure
     */
    public Tlv(byte tag, byte[] value) {
        this.tag = tag & 0xFF;
        if (value != null) {
            length = value.length;
        } else {
            length = 0;
        }
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(tag);
        if (length <= 0x7F) {
            // length that less than 128 requires only 1 byte
            offset = 2;
            stream.write((byte) length);
        } else if (value.length <= 0xFF) {
            // length that more than 127 but less than 256 requires 2 bytes (flags that length > 127 and length itself)
            offset = 3;
            stream.write((byte) LENGTH_REQUIRES_EXTRA_BYTE);
            stream.write((byte) length);
        } else if (value.length <= 0xFFFF) {
            // length that more than 255 but less than 65536 requires 3 bytes (flags that length > 256 and 2 bytes for length itself)
            offset = 4;
            stream.write((byte) LENGTH_REQUIRES_EXTRA_TWO_BYTES);
            stream.write((byte) (value.length >> 8));
            stream.write((byte) length);
        } else {
            // length that more than 65536 is not supported within this protocol
            throw new IllegalArgumentException("Length of value is too large.");
        }
        if (value != null) {
            stream.write(value, 0, length);
        }
        data = stream.toByteArray();
    }

    /**
     * @return the tag
     */
    public int getTag() {
        return tag;
    }

    /**
     * @return value bytes
     */
    public byte[] getValue() {
        return Arrays.copyOfRange(data, offset, offset + length);
    }

    /**
     * @return length of the value bytes
     */
    public int getLength() {
        return length;
    }

    /**
     * @return the offset where value starts from (within raw data)
     */
    public int getOffset() {
        return offset;
    }

    /**
     * @return raw data of tlv blob
     */
    public byte[] getData() {
        return data;
    }

}

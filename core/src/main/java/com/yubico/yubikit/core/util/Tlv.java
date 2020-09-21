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

package com.yubico.yubikit.core.util;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Locale;

import javax.annotation.Nullable;

/**
 * Tag, length, Value structure that helps to parse APDU response data.
 * This class handles simple BER-TLV encoded values where the tag consists of 1-2 bytes.
 */
public class Tlv {
    private static final int LENGTH_REQUIRES_EXTRA_BYTE = 0x81;
    private static final int LENGTH_REQUIRES_EXTRA_TWO_BYTES = 0x82;

    private final int tag;
    private final int length;
    private final byte[] bytes;
    private final int offset;

    /**
     * Creates instance of {@link Tlv}
     *
     * @param bytes      raw bytes that needs to be converted into Tlv
     * @param dataOffset offset within data byte array
     */
    public Tlv(byte[] bytes, int dataOffset) {
        int pointer = 0;
        int tagData = bytes[dataOffset + pointer++] & 0xFF;
        if ((tagData & 0x1f) == 0x1f) {
            tagData = tagData << 8 | (bytes[dataOffset + pointer++] & 0xFF);
        }
        tag = tagData;

        int checkByte = bytes[dataOffset + pointer++] & 0xFF;
        if (checkByte < LENGTH_REQUIRES_EXTRA_BYTE) {
            length = checkByte;
        } else if (checkByte == LENGTH_REQUIRES_EXTRA_BYTE) {
            length = bytes[dataOffset + pointer++] & 0xFF;
        } else if (checkByte == LENGTH_REQUIRES_EXTRA_TWO_BYTES) {
            length = ((bytes[dataOffset + pointer++] & 0xFF) << 8) + (bytes[dataOffset + pointer++] & 0xFF);
        } else {
            length = 0;
        }
        offset = pointer;

        this.bytes = Arrays.copyOfRange(bytes, dataOffset, dataOffset + offset + length);
    }

    /**
     * Creates instance of {@link Tlv}
     *
     * @param tag   the tag of structure
     * @param value the value of structure
     */
    public Tlv(int tag, @Nullable byte[] value) {
        this.tag = tag;
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        if (tag <= 0xFF) {
            stream.write(tag);
        } else if (((tag >> 8) & 0x1F) == 0x1F) {
            stream.write(tag >> 8);
            stream.write(tag & 0xFF);
        } else {
            throw new IllegalArgumentException("Unsupported tag format!");
        }

        if (value != null) {
            length = value.length;
        } else {
            length = 0;
        }
        if (length <= 0x7F) {
            // length that less than 128 requires only 1 byte
            stream.write(length);
        } else if (value.length <= 0xFF) {
            // length that more than 127 but less than 256 requires 2 bytes (flags that length > 127 and length itself)
            stream.write(LENGTH_REQUIRES_EXTRA_BYTE);
            stream.write(length);
        } else if (value.length <= 0xFFFF) {
            // length that more than 255 but less than 65536 requires 3 bytes (flags that length > 256 and 2 bytes for length itself)
            stream.write(LENGTH_REQUIRES_EXTRA_TWO_BYTES);
            stream.write(value.length >> 8);
            stream.write(length & 0xFF);
        } else {
            // length that more than 65536 is not supported within this protocol
            throw new IllegalArgumentException("Length of value is too large.");
        }
        offset = stream.size();
        if (value != null) {
            stream.write(value, 0, length);
        }
        bytes = stream.toByteArray();
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
        return Arrays.copyOfRange(bytes, offset, offset + length);
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
    public byte[] getBytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    @Override
    public String toString() {
        return String.format(Locale.ROOT, "Tlv(0x%x, %d, %s)", tag, length, StringUtils.bytesToHex(getValue()));
    }
}

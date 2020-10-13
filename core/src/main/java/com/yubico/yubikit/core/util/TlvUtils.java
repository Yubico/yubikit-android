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

import com.yubico.yubikit.core.BadResponseException;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helper methods to parse data into multiple of Tlvs
 */
public class TlvUtils {

    /**
     * Converts raw data into list of Tlvs
     *
     * @param data byte array
     * @return list of Tlvs
     */
    public static List<Tlv> parseTlvList(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        List<Tlv> tlvs = new ArrayList<>();
        while (buffer.hasRemaining()) {
            Tlv tlv = Tlv.parseFrom(buffer);
            tlvs.add(tlv);
        }
        return tlvs;
    }

    /**
     * Converts raw data into map of TLVs
     * <p>
     * Iteration order is preserved. If the same tag occurs more than once only the latest will be kept.
     *
     * @param data byte array
     * @return map of Tlv values where the key is tag
     */
    public static Map<Integer, byte[]> parseTlvMap(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        Map<Integer, byte[]> tlvs = new LinkedHashMap<>();
        while (buffer.hasRemaining()) {
            Tlv tlv = Tlv.parseFrom(buffer);
            tlvs.put(tlv.getTag(), tlv.getValue());
        }
        return tlvs;
    }

    /**
     * Converts a List of Tlvs into an encoded array of bytes.
     *
     * @param list list of Tlvs
     * @return byte array
     */
    public static byte[] packTlvList(List<Tlv> list) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (Tlv tlv : list) {
            stream.write(tlv.getBytes(), 0, tlv.getBytes().length);
        }
        return stream.toByteArray();
    }

    /**
     * Converts a Map of TLV data into an encoded array of bytes.
     * NOTE: If order is important use a Map implementation that preserves order, such as LinkedHashMap.
     *
     * @param map the tag-value mappings
     * @return the data encoded as a sequence of TLV values
     */
    public static byte[] packTlvMap(Map<Integer, byte[]> map) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (Map.Entry<Integer, byte[]> entry : map.entrySet()) {
            Tlv tlv = new Tlv(entry.getKey(), entry.getValue());
            byte[] tlvBytes = tlv.getBytes();
            stream.write(tlvBytes, 0, tlvBytes.length);
        }
        return stream.toByteArray();
    }

    /**
     * Decode TLV data, returning only the value
     *
     * @param expectedTag the expected tag value of the given TLV data
     * @param tlvData     the TLV data
     * @return the value of the TLV
     * @throws BadResponseException if the TLV tag differs from expectedTag
     */
    public static byte[] unpackValue(int expectedTag, byte[] tlvData) throws BadResponseException {
        Tlv tlv = Tlv.parse(tlvData, 0, tlvData.length);
        if (tlv.getTag() != expectedTag) {
            throw new BadResponseException(String.format("Expected tag: %02x, got %02x", expectedTag, tlv.getTag()));
        }
        return tlv.getValue();
    }
}

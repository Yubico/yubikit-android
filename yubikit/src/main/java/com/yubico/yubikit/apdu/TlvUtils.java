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

import android.util.SparseArray;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Helper methods to parse data into multiple of Tlvs
 */
public class TlvUtils {

    /**
     * Converts raw data into list of Tlvs
     * @param data byte array
     * @return list of Tlvs
     */
    public static List<Tlv> parseTlvList(byte[] data) {
        List<Tlv> tlvs = new ArrayList<>();
        int offset = 0;
        while (offset < data.length) {
            Tlv tlv = new Tlv(data, offset);
            tlvs.add(tlv);
            offset += tlv.getOffset() + tlv.getLength();
        }
        return tlvs;
    }

    /**
     * Converts raw data into map of Tlvs
     * @param data byte array
     * @return map of Tlv values where the key is tag
     */
    public static SparseArray<byte[]> parseTlvMap(byte[] data) {
        SparseArray<byte[]> tlvs = new SparseArray<>();
        int offset = 0;
        while (offset < data.length) {
            Tlv tlv = new Tlv(data, offset);
            tlvs.put(tlv.getTag(), tlv.getValue());
            offset += tlv.getOffset() + tlv.getLength();
        }
        return tlvs;
    }

    /**
     * Converts list of Tlvs into raw byte array
     * @param list list of Tlvs
     * @return byte array
     */
    public static byte[] TlvToData(List<Tlv> list) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (Tlv tlv : list) {
            stream.write(tlv.getData(), 0, tlv.getData().length);
        }
        return stream.toByteArray();
    }
}

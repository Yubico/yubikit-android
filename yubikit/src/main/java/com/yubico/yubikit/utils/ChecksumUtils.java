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

package com.yubico.yubikit.utils;

/**
 * <p>
 *   Utility methods for calculating and verifying the CRC13239 checksum used
 *   for YubiKeys.
 * </p>
 */
public class ChecksumUtils {
    /**
     * <p>When verifying a checksum the CRC_OK_RESIDUAL should be the remainder</p>
     */
    public static final short CRC_OK_RESIDUAL = (short) 0xf0b8;

    /**
     * <p>Method for calculating a CRC13239 checksum over a byte buffer.</p>
     * @param data byte buffer to be checksummed.
     * @param length how much of the buffer should be checksummed
     * @return CRC13239 checksum
     */

    static public short calculateCrc(byte[] data, int length) {
        int crc = 0xffff;

        for(int index = 0; index < length; index++) {
            int i, j;
            crc ^= data[index] & 0xFF;
            for (i = 0; i < 8; i++) {
                j = crc & 1;
                crc >>= 1;
                if (j == 1) {
                    crc ^= 0x8408;
                }
            }
        }

        return (short) (crc & 0xFFFF);
    }
}

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

public class StringUtils {

    /**
     * Helper method that convert byte array into string for logging
     * @param byteArray array of bytes
     * @return string representation of byte array
     */
    public static String convertBytesToString(byte[] byteArray) {
        return convertBytesToString(byteArray, 0, byteArray.length);
    }

    /**
     * Helper method that convert byte array into string for logging
     * @param byteArray array of bytes
     * @param size the size of array
     * @return string representation of byte array
     */
    public static String convertBytesToString(byte[] byteArray, int size) {
        return convertBytesToString(byteArray, 0, size);
    }

    /**
     * Helper method that convert byte array into string for logging
     * @param byteArray array of bytes
     * @param offset the offset within byteArray
     * @param size the size of array
     * @return string representation of byte array
     */
    public static String convertBytesToString(byte[] byteArray, int offset, int size) {
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < size; i++) {
            sb.append(String.format("%02x ", byteArray[i]));
        }
        return sb.toString();
    }

    /**
     * Helper method that converts int array into bytes array
     * @param ints array of ints
     * @return array of bytes
     */
    public static byte[] byteArrayOfInts(int[] ints) {
        byte[] bytes = new byte[ints.length];
        for (int i = 0; i < ints.length; i++) {
            bytes[i] = (byte)ints[i];
        }
        return bytes;
    }

}

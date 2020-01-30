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

package com.yubico.yubikit.configurator;

import com.yubico.yubikit.exceptions.NotSupportedOperation;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Modhex mapping: https://developers.yubico.com/yubico-c/Manuals/modhex.1.html
 */
public class ModHexUtils {
    public final static char[] MODHEX_ALPHABET = "cbdefghijklnrtuv".toCharArray();

    public final static Map<Character, Integer> MODHEX_TO_HEX = new HashMap<Character, Integer>() {{
        put('c', 0x00);
        put('b', 0x01);
        put('d', 0x02);
        put('e', 0x03);
        put('f', 0x04);
        put('g', 0x05);
        put('h', 0x06);
        put('i', 0x07);
        put('j', 0x08);
        put('k', 0x09);
        put('l', 0x0a);
        put('n', 0x0b);
        put('r', 0x0c);
        put('t', 0x0d);
        put('u', 0x0e);
        put('v', 0x0f);
    }};

    /**
     * Decodes MODHEX encoded string
     * Converts each symbol of input from MODHEX to hex value
     * Note: output is going to be twice shorter, because 2 modhex symbols encode 1 byte of data (Base16)
     * @param modhex byte array of modhex encoded string (character ASCII codes)
     * @return decoded byte array
     */
    public static byte[] convertModHexToHex(byte[] modhex) throws NotSupportedOperation {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte hexValue = 0;
        if (modhex.length % 2 != 0) {
            throw new NotSupportedOperation("Incorrect size of input array");
        }
        for (int i = 0; i < modhex.length; i++) {
            byte symbol = modhex[i];
            // find hex code for each symbol
            Integer code = ModHexUtils.MODHEX_TO_HEX.get((char) symbol);
            if (code == null) {
                throw new NotSupportedOperation("Input value is not in Modhex format");
            }

            // 2 symbols merged into 1 byte
            boolean shift = i % 2 == 0;
            if (shift) {
                hexValue = (byte) (code.byteValue() << 4);
            } else {
                hexValue |= code.byteValue();
                outputStream.write(hexValue);
            }
        }
        return outputStream.toByteArray();
    }
}

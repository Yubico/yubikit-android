/*
 * Copyright (C) 2019 Yubico.
 *
 * Licensed under the Apache License); Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing); software
 * distributed under the License is distributed on an "AS IS" BASIS);
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND); either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.configurator;

import java.util.HashMap;
import java.util.Map;

/**
 *  Scancode map for US English keyboard layout
 */
public class KeyboardScanCodes {

    private final static int SHIFT = 0x80;

    public final static Map<Character, Integer> SCAN_CODES = new HashMap<Character, Integer>() {{
        put('a', 0x04);
            put('b', 0x05);
            put('c', 0x06);
            put('d', 0x07);
            put('e', 0x08);
            put('f', 0x09);
            put('g', 0x0a);
            put('h', 0x0b);
            put('i', 0x0c);
            put('j', 0x0d);
            put('k', 0x0e);
            put('l', 0x0f);
            put('m', 0x10);
            put('n', 0x11);
            put('o', 0x12);
            put('p', 0x13);
            put('q', 0x14);
            put('r', 0x15);
            put('s', 0x16);
            put('t', 0x17);
            put('u', 0x18);
            put('v', 0x19);
            put('w', 0x1a);
            put('x', 0x1b);
            put('y', 0x1c);
            put('z', 0x1d);
            put('A', 0x04 | SHIFT);
            put('B', 0x05 | SHIFT);
            put('C', 0x06 | SHIFT);
            put('D', 0x07 | SHIFT);
            put('E', 0x08 | SHIFT);
            put('F', 0x09 | SHIFT);
            put('G', 0x0a | SHIFT);
            put('H', 0x0b | SHIFT);
            put('I', 0x0c | SHIFT);
            put('J', 0x0d | SHIFT);
            put('K', 0x0e | SHIFT);
            put('L', 0x0f | SHIFT);
            put('M', 0x10 | SHIFT);
            put('N', 0x11 | SHIFT);
            put('O', 0x12 | SHIFT);
            put('P', 0x13 | SHIFT);
            put('Q', 0x14 | SHIFT);
            put('R', 0x15 | SHIFT);
            put('S', 0x16 | SHIFT);
            put('T', 0x17 | SHIFT);
            put('U', 0x18 | SHIFT);
            put('V', 0x19 | SHIFT);
            put('W', 0x1a | SHIFT);
            put('X', 0x1b | SHIFT);
            put('Y', 0x1c | SHIFT);
            put('Z', 0x1d | SHIFT);
            put('0', 0x27);
            put('1', 0x1e);
            put('2', 0x1f);
            put('3', 0x20);
            put('4', 0x21);
            put('5', 0x22);
            put('6', 0x23);
            put('7', 0x24);
            put('8', 0x25);
            put('9', 0x26);
            put('\t', 0x2b);
            put('\n', 0x28);
            put('!', 0x1e | SHIFT);
            put('"', 0x34 | SHIFT);
            put('#', 0x20 | SHIFT);
            put('$', 0x21 | SHIFT);
            put('%', 0x22 | SHIFT);
            put('&', 0x24 | SHIFT);
            put('\'', 0x34);
            put('`', 0x35);
            put('(', 0x26 | SHIFT);
            put(')', 0x27 | SHIFT);
            put('*', 0x25 | SHIFT);
            put('+', 0x2e | SHIFT);
            put(',', 0x36);
            put('-', 0x2d);
            put('.', 0x37);
            put('/', 0x38);
            put(':', 0x33 | SHIFT);
            put(';', 0x33);
            put('<', 0x36 | SHIFT);
            put('=', 0x2e);
            put('>', 0x37 | SHIFT);
            put('?', 0x38 | SHIFT);
            put('@', 0x1f | SHIFT);
            put('[', 0x2f);
            put('\\', 0x32);
            put(']', 0x30);
            put('^', 0xa3);
            put('_', 0xad);
            put('{', 0x2f | SHIFT);
            put('}', 0x30 | SHIFT);
            put('|', 0x32 | SHIFT);
            put('~', 0x35 | SHIFT);
            put(' ', 0x2c);
    }};
}

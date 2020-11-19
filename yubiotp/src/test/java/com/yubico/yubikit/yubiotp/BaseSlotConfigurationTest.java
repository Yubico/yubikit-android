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

package com.yubico.yubikit.yubiotp;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class BaseSlotConfigurationTest {

    @Test
    public void testBuildConfig() {
        byte[] fixed = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        byte[] uid = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
        byte[] key = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
        byte tktFlags = SlotConfiguration.TKTFLAG_APPEND_CR.bit;
        byte[] config = BaseSlotConfiguration.buildConfig(
                fixed,
                uid,
                key,
                (byte) 0,
                tktFlags,
                (byte) 0,
                null
        );

        assertEquals(52, config.length);
        assertEquals(fixed.length, config[44]);
        assertEquals(tktFlags, config[46]);
    }
}
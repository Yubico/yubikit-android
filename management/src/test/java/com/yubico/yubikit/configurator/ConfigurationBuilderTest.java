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

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;

@RunWith(AndroidJUnit4.class)
public class ConfigurationBuilderTest {
    ConfigurationBuilder cfg;

    @Before
    public void setup() {
        cfg = new ConfigurationBuilder();
    }
    @Test
    public void testStructure() {
        byte[] fixed = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        byte[] uid = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
        byte[] key = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
        byte tktFlags = ConfigurationBuilder.TKTFLAG_APPEND_CR;
        cfg.setFixed(fixed);
        cfg.setUid(uid);
        cfg.setKey(ConfigurationBuilder.AES_MODE, key);
        cfg.setTktFlags(tktFlags);
        byte[] config = cfg.build();

        assertEquals(58, config.length);
        assertEquals(fixed.length, config[ConfigurationBuilder.CFG_FIXED_SIZE_OFFS]);
        assertEquals(tktFlags, config[ConfigurationBuilder.CFG_TKT_FLAGS_OFFS]);
    }

    @SuppressWarnings("unused")
    private void dumpHex(byte[] bytes) {
        String out = "";
        for(byte b : bytes) {
            out += String.format("%02x", b);
        }
        System.out.println(out);
    }
}
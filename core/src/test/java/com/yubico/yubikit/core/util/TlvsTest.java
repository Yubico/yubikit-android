/*
 * Copyright (C) 2020 Yubico.
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

import com.yubico.yubikit.core.application.BadResponseException;

import org.junit.Assert;
import org.junit.Test;

public class TlvsTest {
    @Test
    public void testDoubleByteTags() {
        Tlv tlv = Tlv.parse(new byte[]{0x7F, 0x49, 0});
        Assert.assertEquals(0x7F49, tlv.getTag());
        Assert.assertEquals(0, tlv.getLength());

        tlv = Tlv.parse(new byte[]{(byte) 0x80, 0});
        Assert.assertEquals(0x80, tlv.getTag());
        Assert.assertEquals(0, tlv.getLength());

        tlv = new Tlv(0x7F49, null);
        Assert.assertEquals(0x7F49, tlv.getTag());
        Assert.assertEquals(0, tlv.getLength());
        Assert.assertArrayEquals(new byte[]{0x7F, 0x49, 0}, tlv.getBytes());

        tlv = new Tlv(0x80, null);
        Assert.assertEquals(0x80, tlv.getTag());
        Assert.assertEquals(0, tlv.getLength());
        Assert.assertArrayEquals(new byte[]{(byte) 0x80, 0}, tlv.getBytes());
    }

    @Test
    public void testUnwrap() throws BadResponseException {
        Tlvs.unpackValue(0x80, new byte[]{(byte) 0x80, 0});

        Tlvs.unpackValue(0x7F49, new byte[]{0x7F, 0x49, 0});

        byte[] value = Tlvs.unpackValue(0x7F49, new byte[]{0x7F, 0x49, 3, 1, 2, 3});
        Assert.assertArrayEquals(new byte[]{1, 2, 3}, value);
    }
}

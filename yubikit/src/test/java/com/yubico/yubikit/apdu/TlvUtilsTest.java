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
package com.yubico.yubikit.apdu;

import com.yubico.yubikit.exceptions.UnexpectedTagException;

import org.junit.Assert;
import org.junit.Test;

public class TlvUtilsTest {
    @Test
    public void testDoubleByteTags() {
        Tlv tlv = new Tlv(new byte[]{0x7F, 0x49, 0}, 0);
        Assert.assertEquals(0x7F49, tlv.getTag());
        Assert.assertEquals(3, tlv.getOffset());

        tlv = new Tlv(new byte[]{(byte) 0x80, 0}, 0);
        Assert.assertEquals(0x80, tlv.getTag());
        Assert.assertEquals(2, tlv.getOffset());

        tlv = new Tlv(0x7F49, null);
        Assert.assertEquals(0x7F49, tlv.getTag());
        Assert.assertEquals(3, tlv.getOffset());
        Assert.assertArrayEquals(new byte[]{0x7F, 0x49, 0}, tlv.getData());

        tlv = new Tlv(0x80, null);
        Assert.assertEquals(0x80, tlv.getTag());
        Assert.assertEquals(2, tlv.getOffset());
        Assert.assertArrayEquals(new byte[]{(byte) 0x80, 0}, tlv.getData());
    }

    @Test
    public void testUnwrap() throws UnexpectedTagException {
        TlvUtils.unwrapTlv(new byte[]{(byte) 0x80, 0}, 0x80);

        TlvUtils.unwrapTlv(new byte[]{0x7F, 0x49, 0}, 0x7F49);

        byte[] value = TlvUtils.unwrapTlv(new byte[]{0x7F, 0x49, 3, 1, 2, 3}, 0x7F49);
        Assert.assertArrayEquals(new byte[]{1, 2, 3}, value);
    }
}

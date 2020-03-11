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

package com.yubico.yubikit.otp;

import android.nfc.NdefRecord;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

@RunWith(AndroidJUnit4.class)
public class OtpParserTest {
    private static String SAMPLE_OTP_CODE = "ccccccjehedvvcnfbnnjbbicenfbhvnulkrflcbitifv";
    private static final  String YK_PREFIX = "my.yubico.com/yk/#";
    private static final  String NEO_PREFIX = "my.yubico.com/neo/";

    @Test
    public void parseValidPayload() {
        NdefRecord record = new NdefRecord((short) 1, new byte[]{0x55},  null, createNdefData(YK_PREFIX, SAMPLE_OTP_CODE.getBytes(StandardCharsets.UTF_8)));
        String code = OtpParser.parseNdefRecord(record);
        Assert.assertEquals(SAMPLE_OTP_CODE, code);
    }

    @Test
    public void parseValidNeoPayload() {
        NdefRecord record = new NdefRecord((short) 1, new byte[]{0x55},  null, createNdefData(NEO_PREFIX, SAMPLE_OTP_CODE.getBytes(StandardCharsets.UTF_8)));
        String code = OtpParser.parseNdefRecord(record);
        Assert.assertEquals(SAMPLE_OTP_CODE, code);
    }

    @Test
    public void parseInvalidFormatPayload() {
        NdefRecord record = new NdefRecord((short) 1, new byte[]{0x55},  null, createNdefData(NEO_PREFIX, new byte[0]));
        String code = OtpParser.parseNdefRecord(record);
        Assert.assertEquals("", code);

        record = new NdefRecord((short) 1, new byte[]{0x55},  null, null);
        code = OtpParser.parseNdefRecord(record);
        Assert.assertNull(code);
    }

    @Test
    public void parseNotYubicoHost() {
        NdefRecord record = new NdefRecord((short) 1, new byte[]{0x55},  null, createNdefData("another.host.com/yk/#", SAMPLE_OTP_CODE.getBytes(StandardCharsets.UTF_8)));
        String code = OtpParser.parseNdefRecord(record);
        Assert.assertNull(code);
    }

    @Test
    public void parseStaticPassword() {
        NdefRecord record = new NdefRecord((short) 1, new byte[]{0x55},  null, createNdefData(YK_PREFIX, new byte[]{23, 23, 23}));
        String code = OtpParser.parseNdefRecord(record);
        Assert.assertEquals("ttt", code);
    }

    @Test
    public void parseHOTP() {
        NdefRecord record = new NdefRecord((short) 1, new byte[]{0x55},  null, createNdefData(YK_PREFIX, new byte[]{39, 30, 31, 32, 33, 34}));
        String code = OtpParser.parseNdefRecord(record);
        Assert.assertEquals("012345", code);
    }

    private static byte[] createNdefData(String prefix, @NonNull byte[] data) {
        ByteBuffer buffer = ByteBuffer.allocate(prefix.length() + data.length + 1);
        buffer.put((byte) 0x04);
        buffer.put(prefix.getBytes(StandardCharsets.UTF_8));
        buffer.put(data);
        return buffer.array();
    }
}

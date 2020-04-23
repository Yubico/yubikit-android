package com.yubico.yubikit.utils;

import org.junit.Assert;
import org.junit.Test;

public class ChecksumUtilsTest {

    @Test
    public void testCrc() {
        byte[] data = {0x0, 0x1, 0x2, 0x3, 0x4};
        short crc = ChecksumUtils.calculateCrc(data, data.length);
        Assert.assertEquals((short) 62919, crc);
    }

    @Test
    public void testCrc2() {
        byte[] data = {(byte) 0xfe};
        /*
         * >>> test_common.crc16('fe'.decode('hex'))
         * 4470
         * >>>
         */
        short crc = ChecksumUtils.calculateCrc(data, data.length);
        Assert.assertEquals((short) 4470, crc);
    }

    @Test
    public void testCrc3() {
        byte[] data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, /* uid */
                0x30, 0x75, /* use_ctr */
                0x00, 0x09, /* ts_low */
                0x3d, /* ts_high */
                (byte) 0xfa, /* session_ctr */
                0x60, (byte) 0xea /* rnd */
        };
        short crc = ChecksumUtils.calculateCrc(data, data.length);

        Assert.assertEquals((short) 35339, crc);
    }

    @Test
    public void testCrc4() {
        byte[] data = {0x55, (byte) 0xaa, 0x00, (byte) 0xff};
        short crc = ChecksumUtils.calculateCrc(data, data.length);
        Assert.assertEquals((short) 52149, crc);
    }
}

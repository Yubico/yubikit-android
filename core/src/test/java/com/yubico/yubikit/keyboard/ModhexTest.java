package com.yubico.yubikit.keyboard;

import com.yubico.yubikit.testing.Codec;

import org.junit.Assert;
import org.junit.Test;

public class ModhexTest {
    @Test
    public void testDecode() {
        Assert.assertArrayEquals(Codec.fromHex("2d344e83"), Modhex.decode("DTEFFUJE"));
        Assert.assertArrayEquals(Codec.fromHex("69b6481c8baba2b60e8f22179b58cd56"), Modhex.decode("hknhfjbrjnlnldnhcujvddbikngjrtgh"));
        Assert.assertArrayEquals(Codec.fromHex("ecde18dbe76fbd0c33330f1c354871db"), Modhex.decode("urtubjtnuihvntcreeeecvbregfjibtn"));
        Assert.assertArrayEquals("test".getBytes(), Modhex.decode("iFHgiEiF"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testOddLengthString() {
        Modhex.decode("theincrediblehulk");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIllegalCharacter() {
        Modhex.decode("theincrediblehulk!");
    }

    @Test
    public void testEncode() {
        Assert.assertEquals("dteffuje", Modhex.encode(Codec.fromHex("2d344e83")));
        Assert.assertEquals("hknhfjbrjnlnldnhcujvddbikngjrtgh", Modhex.encode(Codec.fromHex("69b6481c8baba2b60e8f22179b58cd56")));
        Assert.assertEquals("urtubjtnuihvntcreeeecvbregfjibtn", Modhex.encode(Codec.fromHex("ecde18dbe76fbd0c33330f1c354871db")));
        Assert.assertEquals("ifhgieif", Modhex.encode("test".getBytes()));
    }
}

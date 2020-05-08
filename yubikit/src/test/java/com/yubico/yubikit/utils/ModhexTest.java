package com.yubico.yubikit.utils;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class ModhexTest {
    @Test
    public void testDecode() {
        Assert.assertArrayEquals(Hex.decode("2d344e83"), Modhex.decode("DTEFFUJE"));
        Assert.assertArrayEquals(Hex.decode("69b6481c8baba2b60e8f22179b58cd56"), Modhex.decode("hknhfjbrjnlnldnhcujvddbikngjrtgh"));
        Assert.assertArrayEquals(Hex.decode("ecde18dbe76fbd0c33330f1c354871db"), Modhex.decode("urtubjtnuihvntcreeeecvbregfjibtn"));
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
        Assert.assertEquals("dteffuje", Modhex.encode(Hex.decode("2d344e83")));
        Assert.assertEquals("hknhfjbrjnlnldnhcujvddbikngjrtgh", Modhex.encode(Hex.decode("69b6481c8baba2b60e8f22179b58cd56")));
        Assert.assertEquals("urtubjtnuihvntcreeeecvbregfjibtn", Modhex.encode(Hex.decode("ecde18dbe76fbd0c33330f1c354871db")));
        Assert.assertEquals("ifhgieif", Modhex.encode("test".getBytes()));
    }
}

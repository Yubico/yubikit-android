package com.yubico.yubikit.core.smartcard;

import org.junit.Assert;
import org.junit.Test;

public class ApduTest {
    @Test
    public void testMixedBytesAndInts() {
        byte cla = 0x7f;
        byte ins = (byte) 0xff;
        int p1 = 0x7f;
        int p2 = 0xff;
        Apdu apdu = new Apdu(cla, ins, p1, p2, null);

        Assert.assertEquals(cla, apdu.getCla());
        Assert.assertEquals(ins, apdu.getIns());
        Assert.assertEquals(cla, apdu.getP1());
        Assert.assertEquals(ins, apdu.getP2());
    }
}

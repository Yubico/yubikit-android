package com.yubico.yubikit.testing.piv;

import org.bouncycastle.util.encoders.Hex;

public class PivTestConstants {
    static final byte[] DEFAULT_MANAGEMENT_KEY = Hex.decode("010203040506070801020304050607080102030405060708");
    static final char[] DEFAULT_PIN = "123456".toCharArray();
    static final char[] DEFAULT_PUK = "12345678".toCharArray();
}

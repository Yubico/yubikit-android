package com.yubico.yubikit.testing;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class Codec {
    public static byte[] fromHex(String hex) {
        return Hex.decode(hex);
    }

    public static byte[] fromBase64(String base64) {
        return Base64.decode(base64);
    }
}

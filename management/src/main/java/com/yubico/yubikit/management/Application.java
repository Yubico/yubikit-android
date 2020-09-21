package com.yubico.yubikit.management;

public enum Application {
    OTP(0x0001),
    U2F(0x0002),
    OPENPGP(0x0008),
    PIV(0x0010),
    OATH(0x0020),
    FIDO2(0x0200);

    public final int bit;

    Application(int bit) {
        this.bit = bit;
    }
}

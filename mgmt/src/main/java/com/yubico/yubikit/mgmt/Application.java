package com.yubico.yubikit.mgmt;

public final class Application {
    public static final int OTP = 0x0001;
    public static final int U2F = 0x0002;
    public static final int OPGP = 0x0008;
    public static final int PIV = 0x0010;
    public static final int OATH = 0x0020;
    public static final int FIDO2 = 0x0200;

    private Application() {
    }

    public enum Type {
        OTP(Application.OTP),
        U2F(Application.U2F),
        OPGP(Application.OPGP),
        PIV(Application.PIV),
        OATH(Application.OATH),
        FIDO2(Application.FIDO2);

        public final int value;

        Type(int value) {
            this.value = value;
        }
    }
}

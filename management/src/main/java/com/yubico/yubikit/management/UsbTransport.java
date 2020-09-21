package com.yubico.yubikit.management;

/**
 * Provides constants for the different USB transports, and the Mode enum for combinations of enabled transports.
 */
public final class UsbTransport {
    public static final int OTP = 0x01;
    public static final int FIDO = 0x02;
    public static final int CCID = 0x04;

    private UsbTransport() {
    }

    public enum Mode {
        OTP((byte) 0x00, UsbTransport.OTP),
        CCID((byte) 0x01, UsbTransport.CCID),
        OTP_CCID((byte) 0x02, UsbTransport.OTP | UsbTransport.CCID),
        FIDO((byte) 0x03, UsbTransport.FIDO),
        OTP_FIDO((byte) 0x04, UsbTransport.OTP | UsbTransport.FIDO),
        FIDO_CCID((byte) 0x05, UsbTransport.FIDO | UsbTransport.CCID),
        OTP_FIDO_CCID((byte) 0x06, UsbTransport.OTP | UsbTransport.FIDO | UsbTransport.CCID);

        public final byte value;
        public final int transports;

        Mode(byte value, int transports) {
            this.value = value;
            this.transports = transports;
        }

        public static Mode getMode(int transports) {
            for (Mode mode : Mode.values()) {
                if (mode.transports == transports) {
                    return mode;
                }
            }
            throw new IllegalArgumentException("Invalid transports for Mode");
        }
    }
}

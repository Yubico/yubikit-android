package com.yubico.yubikit.core.smartcard;

/**
 * Contains constants for APDU status codes (SW1, SW2).
 */
public final class SW {
    public static final short NO_INPUT_DATA = 0x6285;
    public static final short VERIFY_FAIL_NO_RETRY = 0x63C0;
    public static final short MEMORY_ERROR = 0x6581;
    public static final short WRONG_LENGTH = 0x6700;
    public static final short SECURITY_CONDITION_NOT_SATISFIED = 0x6982;
    public static final short AUTH_METHOD_BLOCKED = 0x6983;
    public static final short DATA_INVALID = 0x6984;
    public static final short CONDITIONS_NOT_SATISFIED = 0x6985;
    public static final short COMMAND_NOT_ALLOWED = 0x6986;
    public static final short INCORRECT_PARAMETERS = 0x6A80;
    public static final short FILE_NOT_FOUND = 0x6A82;
    public static final short NO_SPACE = 0x6A84;
    public static final short INVALID_INSTRUCTION = 0x6D00;
    public static final short COMMAND_ABORTED = 0x6F00;
    public static final short OK = (short) 0x9000;

    private SW() {
    }
}

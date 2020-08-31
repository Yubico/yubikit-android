package com.yubico.yubikit.otp;

import com.yubico.yubikit.keyboard.ChecksumUtils;

import javax.annotation.Nullable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Flags and utilities for configuring YubiKey OTP slots.
 * Constants are taken from https://github.com/Yubico/yubikey-personalization
 */
public class Config {
    /* Config structure */
    public static final int FIXED_SIZE = 16;        // Max size of fixed field
    public static final int UID_SIZE = 6;    // Size of secret ID field
    public static final int KEY_SIZE = 16;        // Size of AES key
    public static final int ACC_CODE_SIZE = 6;        // Size of access code to re-program device
    public static final int CONFIG_SIZE = 52; // Size of config struct (excluding current access code)

    /* NDEF structure */
    private static final int NDEF_DATA_SIZE = 54; //Size of the NDEF payload data

    // Yubikey 1 and above
    public static final byte TKTFLAG_TAB_FIRST = 0x01; // Send TAB before first part
    public static final byte TKTFLAG_APPEND_TAB1 = 0x02; // Send TAB after first part
    public static final byte TKTFLAG_APPEND_TAB2 = 0x04; // Send TAB after second part
    public static final byte TKTFLAG_APPEND_DELAY1 = 0x08; // Add 0.5s delay after first part
    public static final byte TKTFLAG_APPEND_DELAY2 = 0x10; // Add 0.5s delay after second part
    public static final byte TKTFLAG_APPEND_CR = 0x20; // Append CR as final character

    // Yubikey 2 and above
    public static final byte TKTFLAG_PROTECT_CFG2 = (byte) 0x80; // Block update of config 2 unless config 2 is configured and has this bit set

    // Configuration flags

    // Yubikey 1 and above
    public static final byte CFGFLAG_SEND_REF = 0x01; // Send reference string (0..F) before data
    public static final byte CFGFLAG_PACING_10MS = 0x04; // Add 10ms intra-key pacing
    public static final byte CFGFLAG_PACING_20MS = 0x08; // Add 20ms intra-key pacing
    public static final byte CFGFLAG_STATIC_TICKET = 0x20; // Static ticket generation

    // Yubikey 1 only
    public static final byte CFGFLAG_TICKET_FIRST = 0x02; // Send ticket first (default is fixed part)
    public static final byte CFGFLAG_ALLOW_HIDTRIG = 0x10; // Allow trigger through HID/keyboard

    // Yubikey 2 and above
    public static final byte CFGFLAG_SHORT_TICKET = 0x02; // Send truncated ticket (half length)
    public static final byte CFGFLAG_STRONG_PW1 = 0x10; // Strong password policy flag #1 (mixed case)
    public static final byte CFGFLAG_STRONG_PW2 = 0x40; // Strong password policy flag #2 (subtitute 0..7 to digits)
    public static final byte CFGFLAG_MAN_UPDATE = (byte) 0x80; // Allow manual (local) update of static OTP

    // Yubikey 2.1 and above
    public static final byte TKTFLAG_OATH_HOTP = 0x40; //  OATH HOTP mode
    public static final byte CFGFLAG_OATH_HOTP8 = 0x02; //  Generate 8 digits HOTP rather than 6 digits
    public static final byte CFGFLAG_OATH_FIXED_MODHEX1 = 0x10; //  First byte in fixed part sent as modhex
    public static final byte CFGFLAG_OATH_FIXED_MODHEX2 = 0x40; //  First two bytes in fixed part sent as modhex
    public static final byte CFGFLAG_OATH_FIXED_MODHEX = 0x50; //  Fixed part sent as modhex
    public static final byte CFGFLAG_OATH_FIXED_MASK = 0x50; //  Mask to get out fixed flags

    // Yubikey 2.2 and above

    public static final byte TKTFLAG_CHAL_RESP = 0x40; // Challenge-response enabled (both must be set)
    public static final byte CFGFLAG_CHAL_YUBICO = 0x20; // Challenge-response enabled - Yubico OTP mode
    public static final byte CFGFLAG_CHAL_HMAC = 0x22; // Challenge-response enabled - HMAC-SHA1
    public static final byte CFGFLAG_HMAC_LT64 = 0x04; // Set when HMAC message is less than 64 bytes
    public static final byte CFGFLAG_CHAL_BTN_TRIG = 0x08; // Challenge-response operation requires button press

    public static final byte EXTFLAG_SERIAL_BTN_VISIBLE = 0x01; // Serial number visible at startup (button press)
    public static final byte EXTFLAG_SERIAL_USB_VISIBLE = 0x02; // Serial number visible in USB iSerial field
    public static final byte EXTFLAG_SERIAL_API_VISIBLE = 0x04; // Serial number visible via API call

    // V2.3 flags only

    public static final byte EXTFLAG_USE_NUMERIC_KEYPAD = 0x08; // Use numeric keypad for digits
    public static final byte EXTFLAG_FAST_TRIG = 0x10; // Use fast trig if only cfg1 set
    public static final byte EXTFLAG_ALLOW_UPDATE = 0x20; // Allow update of existing configuration (selected flags + access code)
    public static final byte EXTFLAG_DORMANT = 0x40; // Dormant configuration (can be woken up and flag removed = requires update flag)

    // V2.4/3.1 flags only

    public static final byte EXTFLAG_LED_INV = (byte) 0x80; // LED idle state is off rather than on

    // Flags valid for update
    private static final byte TKTFLAG_UPDATE_MASK = TKTFLAG_TAB_FIRST | TKTFLAG_APPEND_TAB1 | TKTFLAG_APPEND_TAB2 | TKTFLAG_APPEND_DELAY1 | TKTFLAG_APPEND_DELAY2 | TKTFLAG_APPEND_CR;
    private static final byte CFGFLAG_UPDATE_MASK = CFGFLAG_PACING_10MS | CFGFLAG_PACING_20MS;
    private static final byte EXTFLAG_UPDATE_MASK = EXTFLAG_SERIAL_BTN_VISIBLE | EXTFLAG_SERIAL_USB_VISIBLE | EXTFLAG_SERIAL_API_VISIBLE | EXTFLAG_USE_NUMERIC_KEYPAD | EXTFLAG_FAST_TRIG | EXTFLAG_ALLOW_UPDATE | EXTFLAG_DORMANT | EXTFLAG_LED_INV;

    public static final String DEFAULT_NDEF_URI = "https://my.yubico.com/yk/#";

    /* From nfcforum-ts-rtd-uri-1.0.pdf */
    private static final String[] NDEF_URL_PREFIXES = {
            "http://www.",
            "https://www.",
            "http://",
            "https://",
            "tel:",
            "mailto:",
            "ftp://anonymous:anonymous@",
            "ftp://ftp.",
            "ftps://",
            "sftp://",
            "smb://",
            "nfs://",
            "ftp://",
            "dav://",
            "news:",
            "telnet://",
            "imap:",
            "rtsp://",
            "urn:",
            "pop:",
            "sip:",
            "sips:",
            "tftp:",
            "btspp://",
            "btl2cap://",
            "btgoep://",
            "tcpobex://",
            "irdaobex://",
            "file://",
            "urn:epc:id:",
            "urn:epc:tag:",
            "urn:epc:pat:",
            "urn:epc:raw:",
            "urn:epc:",
            "urn:nfc:"
    };

    static byte[] buildConfig(byte[] fixed, byte[] uid, byte[] key, byte extFlags, byte tktFlags, byte cfgFlags, @Nullable byte[] accCode) {
        if (fixed.length > FIXED_SIZE) {
            throw new IllegalArgumentException("Incorrect length for fixed");
        }
        if (uid.length != UID_SIZE) {
            throw new IllegalArgumentException("Incorrect length for uid");
        }
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Incorrect length for key");
        }
        if (accCode != null && accCode.length != ACC_CODE_SIZE) {
            throw new IllegalArgumentException("Incorrect length for access code");
        }

        ByteBuffer config = ByteBuffer.allocate(CONFIG_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        return config.put(Arrays.copyOf(fixed, FIXED_SIZE))
                .put(uid)
                .put(key)
                .put(accCode == null ? new byte[ACC_CODE_SIZE] : accCode)
                .put((byte) fixed.length)
                .put(extFlags)
                .put(tktFlags)
                .put(cfgFlags)
                .putShort((short)0) // 2 bytes RFU
                .putShort((short) ~ChecksumUtils.calculateCrc(config.array(), config.position()))
                .array();
    }

    static byte[] buildUpdateConfig(byte extFlags, byte tktFlags, byte cfgFlags, @Nullable byte[] accCode) {
        if ((extFlags & ~EXTFLAG_UPDATE_MASK) != 0) {
            throw new IllegalArgumentException("Unsupported ext flags for update");
        }
        if ((tktFlags & ~TKTFLAG_UPDATE_MASK) != 0) {
            throw new IllegalArgumentException("Unsupported tkt flags for update");
        }
        if ((cfgFlags & ~CFGFLAG_UPDATE_MASK) != 0) {
            throw new IllegalArgumentException("Unsupported cfg flags for update");
        }
        return buildConfig(new byte[0], new byte[UID_SIZE], new byte[KEY_SIZE], extFlags, tktFlags, cfgFlags, accCode);
    }

    static byte[] buildNdefConfig(String uri) {
        byte idCode = 0;
        for (int i = 0; i < NDEF_URL_PREFIXES.length; i++) {
            String prefix = NDEF_URL_PREFIXES[i];
            if (uri.startsWith(prefix)) {
                idCode = (byte) (i + 1);
                uri = uri.substring(prefix.length());
                break;
            }
        }
        byte[] uriBytes = uri.getBytes(StandardCharsets.UTF_8);
        int dataLength = 1 + uriBytes.length;
        if (dataLength > NDEF_DATA_SIZE) {
            throw new IllegalArgumentException("URI payload too large");
        }
        return ByteBuffer.allocate(2 + NDEF_DATA_SIZE)
                .put((byte) dataLength)
                .put((byte) 'U')
                .put(idCode)
                .put(uriBytes)
                .array();
    }
}

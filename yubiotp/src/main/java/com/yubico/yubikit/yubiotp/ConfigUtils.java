package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.otp.ChecksumUtils;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import javax.annotation.Nullable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Flags and utilities for configuring YubiKey OTP slots.
 * Constants are taken from https://github.com/Yubico/yubikey-personalization
 */
class ConfigUtils {
    // Config structure
    static final int FIXED_SIZE = 16;        // Max size of fixed field
    static final int UID_SIZE = 6;    // Size of secret ID field
    static final int KEY_SIZE = 16;        // Size of AES key
    static final int ACC_CODE_SIZE = 6;        // Size of access code to re-program device
    static final int CONFIG_SIZE = 52; // Size of config struct (excluding current access code)

    // NDEF structure
    static final int NDEF_DATA_SIZE = 54; //Size of the NDEF payload data

    // Flags valid for update
    private static final byte TKTFLAG_UPDATE_MASK = SlotConfiguration.TKTFLAG_TAB_FIRST | SlotConfiguration.TKTFLAG_APPEND_TAB1 | SlotConfiguration.TKTFLAG_APPEND_TAB2 | SlotConfiguration.TKTFLAG_APPEND_DELAY1 | SlotConfiguration.TKTFLAG_APPEND_DELAY2 | SlotConfiguration.TKTFLAG_APPEND_CR;
    private static final byte CFGFLAG_UPDATE_MASK = SlotConfiguration.CFGFLAG_PACING_10MS | SlotConfiguration.CFGFLAG_PACING_20MS;
    private static final byte EXTFLAG_UPDATE_MASK = SlotConfiguration.EXTFLAG_SERIAL_BTN_VISIBLE | SlotConfiguration.EXTFLAG_SERIAL_USB_VISIBLE | SlotConfiguration.EXTFLAG_SERIAL_API_VISIBLE | SlotConfiguration.EXTFLAG_USE_NUMERIC_KEYPAD | SlotConfiguration.EXTFLAG_FAST_TRIG | SlotConfiguration.EXTFLAG_ALLOW_UPDATE | SlotConfiguration.EXTFLAG_DORMANT | SlotConfiguration.EXTFLAG_LED_INV;

    // From nfcforum-ts-rtd-uri-1.0.pdf
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

    private static final String DEFAULT_NDEF_URI = "https://my.yubico.com/yk/#";

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

    @SuppressFBWarnings(value = "BIT_AND_ZZ", justification = "Check EXTflag mask for completeness")
    static byte[] buildUpdateConfig(byte extFlags, byte tktFlags, byte cfgFlags, @Nullable byte[] accCode) {
        if ((extFlags & ~EXTFLAG_UPDATE_MASK) != 0) {
            throw new IllegalArgumentException("Unsupported EXT flags for update");
        }
        if ((tktFlags & ~TKTFLAG_UPDATE_MASK) != 0) {
            throw new IllegalArgumentException("Unsupported TKT flags for update");
        }
        if ((cfgFlags & ~CFGFLAG_UPDATE_MASK) != 0) {
            throw new IllegalArgumentException("Unsupported CFG flags for update");
        }
        return buildConfig(new byte[0], new byte[UID_SIZE], new byte[KEY_SIZE], extFlags, tktFlags, cfgFlags, accCode);
    }

    static byte[] buildNdefConfig(@Nullable String uri) {
        if (uri == null) {
            uri = DEFAULT_NDEF_URI;
        }
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

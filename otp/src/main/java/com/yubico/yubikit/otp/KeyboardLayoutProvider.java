package com.yubico.yubikit.otp;

/**
 * This class allows to convert scan codes into unicode characters
 *
 * More about HID Keyboard events and its codes can be read here:
 * https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf
 *
 * Here is some specific to Android details on how it is constructed
 * and why there are no default classes that can do such conversion:
 *
 * There is HID to Android Keyboard key events mapping:
 * https://source.android.com/devices/input/keyboard-devices
 *
 * and looks like this
 * private static final int[]USB_HID_KEYBOARD=new int[]{
        0,0,0,0,0x1d,0x1e,0x1f,0x20,0x20,0x22,0x22,0x24,0x25,0x26,0x26,0x28, //0x0f
        0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x08,0x09, //0x1f
        0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x07,0x42,0x6f,0x43,0x3d,0x3e,0x45,0x46,0x47, //0x2f
        0x48,0x49,0x49,0x4a,0x4b,0x44,0x37,0x38,0x4c,0x73,0x83,0x84,0x85,0x86,0x87,0x88, // 0x3f
        0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x78,0x74,0x79,0x7c,0x7a,0x5c,0x70,0x7b,0x5d,0x16, //0x4f
        0x15,0x14,0x13,0x8f,0x9a,0x9b,0x9c,0x9d,0xa0,0x91,0x92,0x93,0x94,0x95,0x96,0x97, //0x5f
        0x98,0x99,0x90,0x9e,0x49,0x52,0x1a,0xa1,0,0,0,0,0,0,0,0, //0x6f
        0,0,0,0,0,0,0,0,0x56,0,0,0,0,0,0,0xa4, //0x7f
        0x18,0x19,0,0,0,0x9f,0,0,0,0,0,0,0,0,0,0, //0x8f
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, //0x9f
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, //0xaf
        0,0,0,0,0,0,0xa2,0xa3,0,0,0,0,0,0,0,0, //0xbf
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, //0xcf
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, //0xdf
        0x71,0x3b,0x39,0x75,0x72,0x3c,0x3a,0x76,0x55,0x56,0x58,0x57,0x81,0x18,0x19,0xa4, //0xef
        0x40,0x04,0x7d,0x56,0,0x5c,0x5d,0,0,0x1a,0,0xd2 //0xff NOTE:last line is not used in yubi keyboard, first bit is used to show SHIFT_ON state
        };
 * Then each Keyboard event has association with character (depending on input source and keyboard layout).
 *         KeyCharacterMap map = KeyCharacterMap.getKeyboardLayout(KeyCharacterMap.VIRTUAL_KEYBOARD);
 *         boolean shiftOn = (0x80 & hid_key_code) == 0x80;
 *         int code = 0x7f & hid_key_code;
 *         char character = (char)map.get(USB_HID_KEYBOARD[code], shiftOn ? KeyEvent.META_SHIFT_ON : 0);
 *
 * For specific layouts Android supports device specific key layout files with InputDevice
 * https://source.android.com/devices/input/key-character-map-files
 * but external peripheral can be attached only to the USB or Bluetooth bus (Not NFC)
 * So we're not using VIRTUAL_KEYBOARD and not real deviceId
 *
 * The best way to support another layout, we will have to create our own KeyCharacterMap
 * and another mapping to convert key_event into unicode character
 * Since we can skip 2 conversion HID_SCAN_CODE to KEY_CODE then to CHARACTER
 * we can create mapping directly from HID_SCAN_CODES to CHARACTERS
 */
public class KeyboardLayoutProvider {

    public static KeyboardLayout getKeyboardLayout() {
        return DEFAULT_CHARACTER_MAP;
    }

    /**
     * Return keyboard layout specific to input source/language
     * @param inputSource type of keyboard layout
     * @return map from HID scan codes to characters
     */
    public static KeyboardLayout getKeyboardLayout(InputSource inputSource) {
        switch (inputSource) {
            case DE:
                return DE_CHARACTER_MAP;
            case DECH:
                return DECH_CHARACTER_MAP;
            default:
                return DEFAULT_CHARACTER_MAP;
        }
    }

    private final static KeyboardLayout DEFAULT_CHARACTER_MAP = new KeyboardLayout(
        new int[]{
            0, 0, 0, 0, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', //0x0f
            'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '1', '2', //0x1f
            '3', '4', '5', '6', '7', '8', '9', '0', '\n', 0, 0, '\t', ' ', '-', '=', '[', //0x2f
            ']', 0, '\\', ';', '\'', '`', ',', '.', '/' // 0x38
        }, new int[] {
            0, 0, 0, 0, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', //0x8f
            'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '@', // 0x9f
            '#', '$', '%', '^', '&', '*', '(', ')', 0, 0, 0, 0, 0, '_', '+', '{', //0xaf
            '}', 0, '|', ':', '\"', '~', '<', '>', '?' //0xb8
    });


    private final static KeyboardLayout DE_CHARACTER_MAP = new KeyboardLayout(
        new int[]{
            0, 0, 0, 0, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', //0x0f
            'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '1', '2', //0x1f
            '3', '4', '5', '6', '7', '8', '9', '0', '\n', 0, 0, '\t', ' ', 'ß', '´', 'ü',  //0x2f
            '+', 0, '#', 'ö', '\'', '^', ',', '.', '-' //0x38
        }, new int[] {
            0, 0, 0, 0, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', //0x8f
            'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '\"', //0x9f
            '§', '$', '%', '&', '/', '(', ')', '=', 0, 0, 0, 0, 0, '?', '`', 'Ü', // 0xaf
            '*', 0, '>', 'Ö', 'Ä', 0, ';', ':', '_' //0xb8
    });


    private final static KeyboardLayout DECH_CHARACTER_MAP = new KeyboardLayout(
        new int[]{
            0, 0, 0, 0, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', //0x0f
            'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '1', '2', //0x1f
            '3', '4', '5', '6', '7', '8', '9', '0', '\n', 0, 0,  '\t', ' ', 'ß', '´', 'ü', //0x2f
            '+', 0, '#', 'ö', '\'', '^', ',', '.', '-' //0x38
        }, new int[] {
            0, 0, 0, 0, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', //0x8f
            'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '\"', //0x9f
            '§', '$', '%', '&', '/', '(', ')', '=', 0, 0, 0, 0, 0, '?', '`', 'Ü', // 0xaf
            '*', 0, '>', 'Ö', 'Ä', 0, ';', ':', '_' //0xb8
    });

}

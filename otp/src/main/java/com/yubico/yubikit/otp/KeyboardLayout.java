package com.yubico.yubikit.otp;

/**
 * Mapping of keys/HID scan codes from YubiKey (as keyboard) to Unicode characters
 */
public class KeyboardLayout {
    private final int[] characterMap;
    private final int[] characterShiftedMap;

    public KeyboardLayout(int[] characterMap, int[] characterShiftedMap) {
        this.characterMap = characterMap;
        this.characterShiftedMap = characterShiftedMap;
    }

    int get(int keyCode, boolean isShifted) {
        if (isShifted) {
            if (keyCode >= characterShiftedMap.length) {
                return 0;
            }
            return characterShiftedMap[keyCode];
        } else {
            if (keyCode >= characterMap.length) {
                return 0;
            }
            return characterMap[keyCode];
        }
    }
}

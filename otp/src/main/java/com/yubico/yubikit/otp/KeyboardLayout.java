package com.yubico.yubikit.otp;

class KeyboardLayout {
    private final int[] characterMap;
    private final int[] characterShiftedMap;

    KeyboardLayout(int[] characterMap, int[] characterShiftedMap) {
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

package com.yubico.yubikit.core.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RandomUtils {
    public static byte[] getRandomBytes(int length) {
        byte[] bytes = new byte[length];
        try {
            SecureRandom.getInstanceStrong().nextBytes(bytes);
        } catch (NoSuchAlgorithmException e) {
            new SecureRandom().nextBytes(bytes);
        }
        return bytes;
    }
}

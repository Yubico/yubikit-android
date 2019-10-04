package com.yubico.yubikit.demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.LocalDateTime;

public class TestUtil {
    public static String getUsername() {
        LocalDateTime now = LocalDateTime.now();
        int year = now.getYear();
        int month = now.getMonthValue();
        int day = now.getDayOfMonth();
        int hour = now.getHour();
        int minute = now.getMinute();
        int second = now.getSecond();
        return String.format("u%d%02d%02d%02d%02d%02d", year, month, day, hour, minute, second);
    }

    public static String getFixedPwd() {
        return "1111";
    }

    // private
    private static void runShellCommand(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}

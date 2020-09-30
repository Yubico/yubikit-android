/*
 * Copyright (C) 2020 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.Version;

import javax.annotation.Nullable;

public interface SlotConfiguration {
    // Constants in this file come from https://github.com/Yubico/yubikey-personalization/blob/master/ykcore/ykdef.h

    // Yubikey 1 and above
    byte TKTFLAG_TAB_FIRST = 0x01; // Send TAB before first part
    byte TKTFLAG_APPEND_TAB1 = 0x02; // Send TAB after first part
    byte TKTFLAG_APPEND_TAB2 = 0x04; // Send TAB after second part
    byte TKTFLAG_APPEND_DELAY1 = 0x08; // Add 0.5s delay after first part
    byte TKTFLAG_APPEND_DELAY2 = 0x10; // Add 0.5s delay after second part
    byte TKTFLAG_APPEND_CR = 0x20; // Append CR as final character

    // Yubikey 2 and above
    byte TKTFLAG_PROTECT_CFG2 = (byte) 0x80; // Block update of config 2 unless config 2 is configured and has this bit set

    // Configuration flags

    // Yubikey 1 and above
    byte CFGFLAG_SEND_REF = 0x01; // Send reference string (0..F) before data
    byte CFGFLAG_PACING_10MS = 0x04; // Add 10ms intra-key pacing
    byte CFGFLAG_PACING_20MS = 0x08; // Add 20ms intra-key pacing
    byte CFGFLAG_STATIC_TICKET = 0x20; // Static ticket generation

    // Yubikey 1 only
    byte CFGFLAG_TICKET_FIRST = 0x02; // Send ticket first (default is fixed part)
    byte CFGFLAG_ALLOW_HIDTRIG = 0x10; // Allow trigger through HID/keyboard

    // Yubikey 2 and above
    byte CFGFLAG_SHORT_TICKET = 0x02; // Send truncated ticket (half length)
    byte CFGFLAG_STRONG_PW1 = 0x10; // Strong password policy flag #1 (mixed case)
    byte CFGFLAG_STRONG_PW2 = 0x40; // Strong password policy flag #2 (subtitute 0..7 to digits)
    byte CFGFLAG_MAN_UPDATE = (byte) 0x80; // Allow manual (local) update of static OTP

    // Yubikey 2.1 and above
    byte TKTFLAG_OATH_HOTP = 0x40; //  OATH HOTP mode
    byte CFGFLAG_OATH_HOTP8 = 0x02; //  Generate 8 digits HOTP rather than 6 digits
    byte CFGFLAG_OATH_FIXED_MODHEX1 = 0x10; //  First byte in fixed part sent as modhex
    byte CFGFLAG_OATH_FIXED_MODHEX2 = 0x40; //  First two bytes in fixed part sent as modhex
    byte CFGFLAG_OATH_FIXED_MODHEX = 0x50; //  Fixed part sent as modhex

    // Yubikey 2.2 and above
    byte TKTFLAG_CHAL_RESP = 0x40; // Challenge-response enabled (both must be set)
    byte CFGFLAG_CHAL_YUBICO = 0x20; // Challenge-response enabled - Yubico OTP mode
    byte CFGFLAG_CHAL_HMAC = 0x22; // Challenge-response enabled - HMAC-SHA1
    byte CFGFLAG_HMAC_LT64 = 0x04; // Set when HMAC message is less than 64 bytes
    byte CFGFLAG_CHAL_BTN_TRIG = 0x08; // Challenge-response operation requires button press

    byte EXTFLAG_SERIAL_BTN_VISIBLE = 0x01; // Serial number visible at startup (button press)
    byte EXTFLAG_SERIAL_USB_VISIBLE = 0x02; // Serial number visible in USB iSerial field
    byte EXTFLAG_SERIAL_API_VISIBLE = 0x04; // Serial number visible via API call

    // V2.3 flags only
    byte EXTFLAG_USE_NUMERIC_KEYPAD = 0x08; // Use numeric keypad for digits
    byte EXTFLAG_FAST_TRIG = 0x10; // Use fast trig if only cfg1 set
    byte EXTFLAG_ALLOW_UPDATE = 0x20; // Allow update of existing configuration (selected flags + access code)
    byte EXTFLAG_DORMANT = 0x40; // Dormant configuration (can be woken up and flag removed = requires update flag)

    // V2.4/3.1 flags only
    byte EXTFLAG_LED_INV = (byte) 0x80; // LED idle state is off rather than on

    Version getMinimumVersion();

    byte[] getConfig(@Nullable byte[] accCode);
}
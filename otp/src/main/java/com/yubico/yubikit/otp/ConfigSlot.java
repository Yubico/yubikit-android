/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.otp;

/**
 * Enumaration of slots on YubiKey (used as commands to program/configure YubiKey)
 */
enum ConfigSlot {
    DUMMY(0x0),
    CONFIG_1(0x1),
    NAV(0x2),
    CONFIG_2( 0x3),
    UPDATE_1( 0x4),
    UPDATE_2(0x5),
    SWAP( 0x6),
    NDEF_1(0x8),
    NDEF_2( 0x9),
    DEVICE_SERIAL(0x10),
    DEVICE_CONFIGURATION(0x11),
    SCAN_MAP(0x12),
    YUBIKEY_4_CAPABILITIES(0x13),
    CHALLENGE_OTP_1(0x20),
    CHALLENGE_OTP_2(0x28),
    CHALLENGE_HMAC_1(0x30),
    CHALLENGE_HMAC_2(0x38);

    /**
     * The one-byte address of a slot.
     */
    public final byte value;

    ConfigSlot(final int value) {
        this.value = (byte) value;
    }
}
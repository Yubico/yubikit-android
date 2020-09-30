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

import com.yubico.yubikit.core.NotSupportedOperation;
import com.yubico.yubikit.core.Version;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Configures the YubiKey to return an OATH-HOTP code on touch
 */
public class HotpSlotConfiguration extends KeyboardSlotConfiguration<HotpSlotConfiguration> {
    private static final int HMAC_KEY_SIZE = 20;      // Size of OATH-HOTP key (key field + first 4 of UID field)

    /**
     * Creates an OATH-HOTP configuration with default settings.
     *
     * @param secret the shared secret for the OATH-TOTP credential
     */
    public HotpSlotConfiguration(byte[] secret) {
        super(new Version(2, 2, 0));

        if (secret.length > HMAC_KEY_SIZE) {
            throw new NotSupportedOperation("key lengths >20 bytes is not supported");
        }

        // Secret is packed into key and uid
        ByteBuffer.wrap(ByteBuffer.allocate(ConfigUtils.KEY_SIZE + ConfigUtils.UID_SIZE).put(secret).array()).get(key).get(uid);

        updateTktFlags(TKTFLAG_OATH_HOTP, true);
        updateTktFlags(CFGFLAG_OATH_FIXED_MODHEX2, true);
    }

    @Override
    protected HotpSlotConfiguration getThis() {
        return this;
    }

    /**
     * If set, output an 8 digit OATH-HOTP code instead of a 6 digit code.
     *
     * @param digits8 true to use 8 digits of code output.
     * @return the configuration for chaining
     */
    public HotpSlotConfiguration digits8(boolean digits8) {
        return updateCfgFlags(CFGFLAG_OATH_HOTP8, digits8);
    }

    /**
     * Configure OATH token id with a provided value.
     * The standard OATH token id for a Yubico YubiKey is (MODHEX) OO=ub, TT=he, (BCD) UUUUUUUU=serial number.
     * <p>
     * The reason for the decimal serial number is to make it easy for humans to correlate the serial number on the back of the YubiKey to an entry in a list of associated tokens for example.
     * <p>
     * NOTE: If fixedModhex1 and fixedModhex2 are BOTH set, the entire token id will be output in MODHEX.
     *
     * @param tokenId      the raw token ID value
     * @param fixedModhex1 output the first byte of the token ID as MODHEX
     * @param fixedModhex2 output the first two bytes of the token ID as MODHEX
     * @return the configuration for chaining
     */
    public HotpSlotConfiguration tokenId(byte[] tokenId, boolean fixedModhex1, boolean fixedModhex2) {
        if (tokenId.length > ConfigUtils.FIXED_SIZE) {
            throw new IllegalArgumentException("Token ID must be <= 16 bytes");
        }
        fixed = Arrays.copyOf(tokenId, tokenId.length);
        updateCfgFlags(CFGFLAG_OATH_FIXED_MODHEX1, fixedModhex1);
        return updateCfgFlags(CFGFLAG_OATH_FIXED_MODHEX2, fixedModhex2);
    }

    /**
     * Set OATH Initial Moving Factor.
     * This is the initial counter value for the YubiKey. This should be a value between 0 and 1048560, evenly dividable by 16.
     *
     * @param imf the initial counter value for the credential
     * @return the configuration for chaining
     */
    public HotpSlotConfiguration imf(int imf) {
        if (imf % 16 != 0 || imf > 0xffff0 || imf < 0) {
            throw new IllegalArgumentException("imf should be between 0 and 1048560, evenly dividable by 16");
        }
        ByteBuffer.wrap(uid, 4, 2).putShort((short) (imf >> 4));
        return getThis();
    }
}

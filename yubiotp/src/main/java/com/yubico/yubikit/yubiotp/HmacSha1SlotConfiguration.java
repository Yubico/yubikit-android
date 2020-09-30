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

import com.yubico.yubikit.core.CommandState;
import com.yubico.yubikit.core.NotSupportedOperation;
import com.yubico.yubikit.core.Version;

import java.nio.ByteBuffer;

/**
 * Configures HMAC-SHA1 challenge response secret on YubiKey
 * ({@link YubiOtpSession#calculateHmacSha1(Slot, byte[], CommandState)} how to use it after configuration)
 */
public class HmacSha1SlotConfiguration extends BaseSlotConfiguration<HmacSha1SlotConfiguration> {
    private static final int HMAC_KEY_SIZE = 20;      // Size of OATH-HOTP key (key field + first 4 of UID field)

    /**
     * Creates a HMAC-SHA1 challenge-response configuration with default settings.
     *
     * @param secret the 20 bytes HMAC key to store
     */
    public HmacSha1SlotConfiguration(byte[] secret) {
        super(new Version(2, 2, 0));

        if (secret.length > HMAC_KEY_SIZE) {
            throw new NotSupportedOperation("key lengths >20 bytes is not supported");
        }

        // Secret is packed into key and uid
        ByteBuffer.wrap(ByteBuffer.allocate(ConfigUtils.KEY_SIZE + ConfigUtils.UID_SIZE).put(secret).array()).get(key).get(uid);

        updateTktFlags(TKTFLAG_CHAL_RESP, true);
        updateCfgFlags(CFGFLAG_CHAL_HMAC, true);
        updateCfgFlags(CFGFLAG_HMAC_LT64, true);
    }

    @Override
    protected HmacSha1SlotConfiguration getThis() {
        return this;
    }

    /**
     * Whether or not to require a user presence check for calculating the response.
     *
     * @param requireTouch if true, any attempt to calculate a response will cause the YubiKey to require touch (default: false)
     * @return the configuration for chaining
     */
    public HmacSha1SlotConfiguration requireTouch(boolean requireTouch) {
        return updateCfgFlags(CFGFLAG_CHAL_BTN_TRIG, requireTouch);
    }

    /**
     * Whether or not challenges sent to this slot are less than 64 bytes long or not.
     *
     * @param lt64 if false, all challenges must be exactly 64 bytes long (default: true)
     * @return the configuration for chaining
     */
    public HmacSha1SlotConfiguration lt64(boolean lt64) {
        return updateCfgFlags(CFGFLAG_HMAC_LT64, lt64);
    }
}

/*
 * Copyright (C) 2023 Yubico.
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

package com.yubico.yubikit.openpgp;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.util.Tlvs;

import java.nio.ByteBuffer;
import java.util.Map;

public class SecuritySupportTemplate {
    static private final int TAG_SIGNATURE_COUNTER = 0x93;
    private final int signatureCounter;

    public SecuritySupportTemplate(int signatureCounter) {
        this.signatureCounter = signatureCounter;
    }

    public int getSignatureCounter() {
        return signatureCounter;
    }

    static SecuritySupportTemplate parse(byte[] encoded) {
        try {
            Map<Integer, byte[]> data = Tlvs.decodeMap(Tlvs.unpackValue(Do.SECURITY_SUPPORT_TEMPLATE, encoded));
            ByteBuffer buf = ByteBuffer.wrap(data.get(TAG_SIGNATURE_COUNTER));
            return new SecuritySupportTemplate(((buf.get() & 0xff) << 16) | buf.getShort());
        } catch (BadResponseException e) {
            throw new IllegalArgumentException(e);
        }
    }
}

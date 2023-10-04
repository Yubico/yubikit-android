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
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;

import java.nio.ByteBuffer;
import java.util.List;

class ExtendedLengthInfo {
    private final int requestMaxBytes;
    private final int responseMaxBytes;

    ExtendedLengthInfo(int requestMaxBytes, int responseMaxBytes) {
        this.requestMaxBytes = requestMaxBytes;
        this.responseMaxBytes = responseMaxBytes;
    }

    public int getRequestMaxBytes() {
        return requestMaxBytes;
    }

    public int getResponseMaxBytes() {
        return responseMaxBytes;
    }

    static ExtendedLengthInfo parse(byte[] encoded) {
        List<Tlv> tlvs = Tlvs.decodeList(encoded);
        try {
            return new ExtendedLengthInfo(
                    0xffff & ByteBuffer.wrap(Tlvs.unpackValue(0x02, tlvs.get(0).getBytes())).getShort(),
                    0xffff & ByteBuffer.wrap(Tlvs.unpackValue(0x02, tlvs.get(1).getBytes())).getShort()
            );
        } catch (BadResponseException e) {
            throw new IllegalArgumentException(e);
        }
    }
}

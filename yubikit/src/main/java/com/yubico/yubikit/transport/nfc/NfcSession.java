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

package com.yubico.yubikit.transport.nfc;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;

import androidx.annotation.NonNull;

import com.yubico.yubikit.transport.Iso7816Connection;
import com.yubico.yubikit.transport.YubiKeySession;

import java.io.IOException;

public class NfcSession implements YubiKeySession {

    /**
     * Represents an NFC tag that has been discovered.
     */
    private final Tag tag;

    /**
     * Instantiates session for nfc tag interaction
     * @param tag the tag that has been discovered
     */
    NfcSession(@NonNull Tag tag) {
        this.tag = tag;
    }

    /**
     * @return NFC tag that has been discovered
     */
    public Tag getTag() {
        return tag;
    }


    @Override
    public @NonNull
    Iso7816Connection openIso7816Connection() throws IOException {
        IsoDep card = IsoDep.get(tag);
        if (card == null) {
            throw new IOException("the tag does not support ISO-DEP");
        }
        card.connect();
        return new NfcIso7816Connection(card);
    }
}

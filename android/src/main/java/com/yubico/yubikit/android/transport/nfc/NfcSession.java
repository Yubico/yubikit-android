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

package com.yubico.yubikit.android.transport.nfc;

import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.Ndef;

import com.yubico.yubikit.iso7816.Iso7816Connection;
import com.yubico.yubikit.android.YubiKeySession;

import java.io.IOException;

public class NfcSession implements YubiKeySession {

    /**
     * Represents an NFC tag that has been discovered.
     */
    private final Tag tag;

    private final int timeout;

    /**
     * Instantiates session for nfc tag interaction
     *
     * @param tag the tag that has been discovered
     */
    NfcSession(Tag tag, int timeout) {
        this.tag = tag;
        this.timeout = timeout;
    }

    /**
     * @return NFC tag that has been discovered
     */
    public Tag getTag() {
        return tag;
    }

    @Override
    public Iso7816Connection openIso7816Connection() throws IOException {
        IsoDep card = IsoDep.get(tag);
        if (card == null) {
            throw new IOException("the tag does not support ISO-DEP");
        }
        card.setTimeout(timeout);
        card.connect();
        return new NfcIso7816Connection(card);
    }

    public byte[] readNdef() throws IOException {
        try(Ndef ndef = Ndef.get(tag)) {
            if (ndef != null) {
                ndef.connect();
                NdefMessage message = ndef.getNdefMessage();
                if (message != null) {
                    return message.toByteArray();
                }
            }
        } catch (FormatException e) {
            throw new IOException(e);
        }
        throw new IOException("NDEF data missing or invalid");
    }
}

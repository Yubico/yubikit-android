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

import com.yubico.yubikit.apdu.Apdu;
import com.yubico.yubikit.apdu.ApduResponse;
import com.yubico.yubikit.transport.Iso7816Connection;
import com.yubico.yubikit.utils.Logger;
import com.yubico.yubikit.utils.StringUtils;

import java.io.IOException;

/**
 * NFC service for interacting with the YubiKey
 */
public class NfcIso7816Connection implements Iso7816Connection {

    /**
     * Provides access to ISO-DEP (ISO 14443-4) properties and I/O operations on a {@link Tag}.
     */
    private IsoDep card;

    /**
     * Instantiates session for nfc tag interaction
     * @param card the tag that has been discovered
     */
    NfcIso7816Connection(@NonNull IsoDep card) {
        this.card = card;
        Logger.d("nfc connection opened");
    }

    @Override
    public void setTimeout(int timeoutMs) {
        Logger.d("nfc connection switching timeout from " + card.getTimeout() + " to " + timeoutMs);
        card.setTimeout(timeoutMs);
    }

    @Override
    public ApduResponse execute(Apdu command) throws IOException {
        Logger.d("sent: " + StringUtils.convertBytesToString(command.getCommandData()));
        byte[] received = card.transceive(command.getCommandData());
        Logger.d("received: " + StringUtils.convertBytesToString(received));
        return new ApduResponse(received);
    }

    @Override
    public void close() throws IOException {
        card.close();
        Logger.d("nfc connection closed");
    }

    @Override
    public byte[] getAtr() {
        return card.getHistoricalBytes();
    }
}
/*
 * Copyright (C) 2019-2022 Yubico.
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

import android.nfc.Tag;
import android.nfc.tech.IsoDep;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.util.StringUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * NFC service for interacting with the YubiKey
 */
public class NfcSmartCardConnection implements SmartCardConnection {

    /**
     * Provides access to ISO-DEP (ISO 14443-4) properties and I/O operations on a {@link Tag}.
     */
    private final IsoDep card;

    private static final Logger logger = LoggerFactory.getLogger(NfcSmartCardConnection.class);

    /**
     * Instantiates session for nfc tag interaction
     *
     * @param card the tag that has been discovered
     */
    NfcSmartCardConnection(IsoDep card) {
        this.card = card;
        logger.debug("nfc connection opened");
    }

    @Override
    public Transport getTransport() {
        return Transport.NFC;
    }

    @Override
    public boolean isExtendedLengthApduSupported() {
        return card.isExtendedLengthApduSupported();
    }

    @Override
    public byte[] sendAndReceive(byte[] apdu) throws IOException {
        logger.trace("sent: {}", StringUtils.bytesToHex(apdu));
        byte[] received = card.transceive(apdu);
        logger.trace("received: {}", StringUtils.bytesToHex(received));
        return received;
    }

    @Override
    public void close() throws IOException {
        card.close();
        logger.debug("nfc connection closed");
    }

    @Override
    public byte[] getAtr() {
        byte[] historicalBytes = card.getHistoricalBytes();
        return historicalBytes != null ? historicalBytes.clone() : new byte[]{};
    }
}
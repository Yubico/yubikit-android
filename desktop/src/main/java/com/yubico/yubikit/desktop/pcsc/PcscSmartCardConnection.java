/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.desktop.pcsc;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.util.StringUtils;

import java.io.IOException;
import java.util.Arrays;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

public class PcscSmartCardConnection implements SmartCardConnection {
    private final Card card;
    private final Transport transport;
    private final CardChannel cardChannel;

    public PcscSmartCardConnection(Card card) throws IOException {
        this.card = card;
        this.transport = (card.getATR().getBytes()[1] & 0xf0) == 0xf0 ? Transport.USB : Transport.NFC;
        try {
            card.beginExclusive();
            this.cardChannel = card.getBasicChannel();
        } catch (CardException e) {
            throw new IOException(e);
        }
    }

    @Override
    public Transport getTransport() {
        return transport;
    }

    @Override
    public boolean isExtendedLengthApduSupported() {
        return false; //TODO
    }

    @Override
    public void close() throws IOException {
        Logger.d("Closing CCID connection");
        try {
            card.endExclusive();
        } catch (CardException e) {
            throw new IOException(e);
        }
    }

    @Override
    public byte[] sendAndReceive(byte[] apdu) throws IOException {
        try {
            Logger.d(apdu.length + " bytes sent over PCSC: " + StringUtils.bytesToHex(apdu));
            if (apdu.length < 5) {
                // CardChannel.transmit requires at least 5 bytes.
                apdu = Arrays.copyOf(apdu, 5);
            }
            byte[] response = cardChannel.transmit(new CommandAPDU(apdu)).getBytes();
            Logger.d(response.length + " bytes received: " + StringUtils.bytesToHex(response));
            return response;
        } catch (CardException e) {
            throw new IOException(e);
        }
    }
}
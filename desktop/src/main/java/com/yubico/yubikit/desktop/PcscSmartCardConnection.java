package com.yubico.yubikit.desktop;

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
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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

public class NfcPcscDevice extends PcscDevice {
    private static final byte[] NDEF_AID = new byte[]{(byte) 0xd2, 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01};

    public NfcPcscDevice(CardTerminal terminal) {
        super(terminal);
    }

    @Override
    public Transport getTransport() {
        return Transport.NFC;
    }

    /**
     * Reads the NDEF record from a YubiKey over NFC.
     * This is only available when connecting over NFC, and only if the YubiKey has been configured
     * to output one of its OTP slots over NDEF.
     *
     * @return the raw NDEF record
     * @throws IOException                      in case of connection error
     * @throws ApduException                    in case of communication error
     * @throws ApplicationNotAvailableException in case the NDEF applet isn't available
     */
    public byte[] readNdef() throws IOException, ApduException, ApplicationNotAvailableException {
        try (SmartCardProtocol ndef = new SmartCardProtocol(openIso7816Connection())) {
            ndef.select(NDEF_AID);

            ndef.sendAndReceive(new Apdu(0x00, 0xa4, 0x00, 0x0C, new byte[]{(byte) 0xe1, 0x04}));
            byte[] resp = ndef.sendAndReceive(new Apdu(0x00, 0xb0, 0, 0, null));
            int ndefLen = resp[1];
            ByteBuffer buf = ByteBuffer.allocate(ndefLen).put(resp, 2, resp.length - 2);
            while (buf.position() < ndefLen) {
                buf.put(ndef.sendAndReceive(new Apdu(0x00, 0xb0, 0, buf.position(), null)));
            }
            return buf.array();
        }
    }
}

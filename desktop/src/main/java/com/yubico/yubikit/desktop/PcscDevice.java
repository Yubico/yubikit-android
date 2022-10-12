package com.yubico.yubikit.desktop;

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

public class PcscDevice implements YubiKeyDevice {
    private static final byte[] NDEF_AID = new byte[]{(byte) 0xd2, 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01};

    private final ExecutorService executorService = Executors.newSingleThreadExecutor();
    private final CardTerminal terminal;
    private final Transport transport;

    public PcscDevice(CardTerminal terminal) {
        this.terminal = terminal;

        // If the terminal has YubiKey in the name, it's connected via USB. Otherwise we assume it's NFC
        if (terminal.getName().toLowerCase().contains("yubikey")) {
            transport = Transport.USB;
        } else {
            transport = Transport.NFC;
        }
    }

    public String getReaderName() {
        return terminal.getName();
    }

    @Override
    public Transport getTransport() {
        return transport;
    }

    public SmartCardConnection openIso7816Connection() throws IOException {
        try {
            return new PcscSmartCardConnection(terminal.connect("T=1"));
        } catch (CardException e) {
            throw new IOException(e);
        }
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

    @Override
    public boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType) {
        return connectionType.isAssignableFrom(PcscSmartCardConnection.class);
    }

    @Override
    public <T extends YubiKeyConnection> void requestConnection(Class<T> connectionType, Callback<Result<T, IOException>> callback) {
        if (!supportsConnection(connectionType)) {
            throw new IllegalStateException("Unsupported connection type");
        }
        executorService.submit(() -> {
            try {
                callback.invoke(Result.success(connectionType.cast(new PcscSmartCardConnection(terminal.connect("T=1")))));
            } catch (CardException e) {
                callback.invoke(Result.failure(new IOException(e)));
            } catch (IOException e) {
                callback.invoke(Result.failure(e));
            }
        });
    }
}

package com.yubico.yubikit.android;

import com.yubico.yubikit.iso7816.Iso7816Connection;

import java.io.IOException;

public interface YubiKeySession {
    /**
     * Opens a ISO-7816 connection to the YubiKey using the USB CCID (smart card) transport or NFC.
     *
     * @return a session for communication with the YubiKey
     * @throws IOException if ISO-7816 isn't available, or on communication error
     */
    Iso7816Connection openIso7816Connection() throws IOException;
}

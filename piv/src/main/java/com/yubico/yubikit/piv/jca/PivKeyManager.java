package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;

import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.annotation.Nullable;
import javax.net.ssl.X509ExtendedKeyManager;

public class PivKeyManager extends X509ExtendedKeyManager {
    private final PivSession piv;
    @Nullable
    private final Pin pin;

    PivKeyManager(PivSession pivSession, @Nullable Pin pin) {
        this.piv = pivSession;
        this.pin = pin;
    }

    private Slot slotForAlias(String alias) {
        return Slot.valueOf(alias);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[] { Slot.AUTHENTICATION.name() };
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return Slot.AUTHENTICATION.name();
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[] { "piv" };
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return "piv";
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        try {
            return new X509Certificate[] { piv.getCertificate(slotForAlias(alias)) };
        } catch (IOException | ApduException | BadResponseException e) {
            Logger.e("Failed getting certificate key: " + alias, e);
            return null;
        }
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        try {
            Slot slot = slotForAlias(alias);
            KeyType keyType = KeyType.fromKey(piv.getCertificate(slot).getPublicKey());
            return PivPrivateKey.of(piv, slot, keyType, pin);
        } catch (IOException | ApduException | BadResponseException e) {
            Logger.e("Failed getting private key: " + alias, e);
            return null;
        }
    }
}

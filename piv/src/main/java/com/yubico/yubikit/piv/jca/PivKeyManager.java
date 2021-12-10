package com.yubico.yubikit.piv.jca;

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
    private final PivPrivateKey privateKey;
    private final X509Certificate[] certificates;

    public PivKeyManager(PivPrivateKey privateKey, X509Certificate[] certificates) {
        this.privateKey = privateKey;
        this.certificates = Arrays.copyOf(certificates, certificates.length);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[] { "YKPiv" };
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return "YKPiv";
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[] { "YKPiv" };
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return "YKPiv";
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return Arrays.copyOf(certificates, certificates.length);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return privateKey;
    }
}

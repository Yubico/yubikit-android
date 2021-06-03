package com.yubico.yubikit.piv.jca;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

public class PivKeyManagerFactorySpi extends KeyManagerFactorySpi {
    private KeyManager[] keyManagers = new KeyManager[0];

    @Override
    protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        throw new KeyStoreException("Unsupported");
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        if (spec instanceof PivManagerFactoryParameters) {
            PivManagerFactoryParameters parameters = (PivManagerFactoryParameters) spec;
            keyManagers = new KeyManager[]{new PivKeyManager(parameters.piv, parameters.pin)};
        } else {
            throw new InvalidAlgorithmParameterException("Must be instance of PivManagerFactoryParameters");
        }
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        return keyManagers;
    }
}

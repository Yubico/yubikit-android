package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.InvalidPinException;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Objects;
import java.util.function.Function;

import javax.annotation.Nullable;

public class PivKeyStoreSpi extends KeyStoreSpi {
    @Nullable
    private PivSession piv;

    @Override
    public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
        Objects.requireNonNull(piv);
        Slot slot = parseAlias(alias);
        PivSessionProvider provider;
        if(password != null) {
            provider = new PivSessionProvider.FromInstanceWithPin(piv, password);
        } else {
            provider = new PivSessionProvider.FromInstance(piv);
        }
        PublicKey publicKey;
        try {
            if (piv.supports(PivSession.FEATURE_METADATA)) {
                publicKey = piv.getSlotMetadata(slot).getPublicKey();
            } else {
                publicKey = piv.getCertificate(slot).getPublicKey();
            }
        } catch (IOException | ApduException e) {
            throw new RuntimeException(e);
        } catch (BadResponseException e) {
            throw new UnrecoverableKeyException("No way to infer KeyType, use 'SLOT/KEYTYPE' (eg. '9a/RSA2048') alias.");
        }
        return PivPrivateKey.of(publicKey, slot, provider);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        return new Certificate[]{engineGetCertificate(alias)};
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        Objects.requireNonNull(piv);
        Slot slot = parseAlias(alias);
        try {
            return piv.getCertificate(slot);
        } catch (IOException | ApduException | BadResponseException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    @Nullable
    public Date engineGetCreationDate(String alias) {
        return null;
    }

    @Override
    public void engineSetEntry(String alias, KeyStore.Entry entry, KeyStore.ProtectionParameter protParam) throws KeyStoreException {
        Objects.requireNonNull(piv);
        Slot slot = parseAlias(alias);

        PrivateKey privateKey = null;
        Certificate certificate;
        if (entry instanceof KeyStore.TrustedCertificateEntry) {
            if (protParam != null) {
                throw new KeyStoreException("Certificate cannot use protParam");
            }
            certificate = ((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate();
        } else if (entry instanceof KeyStore.PrivateKeyEntry) {
            certificate = ((KeyStore.PrivateKeyEntry) entry).getCertificate();
            privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        } else {
            throw new KeyStoreException("Unsupported KeyStore entry.");
        }

        if (certificate != null) {
            if (!(certificate instanceof X509Certificate)) {
                throw new KeyStoreException("Certificate must be X509Certificate");
            }
        }

        if (privateKey != null) {
            PinPolicy pinPolicy = PinPolicy.DEFAULT;
            TouchPolicy touchPolicy = TouchPolicy.DEFAULT;
            if (protParam != null) {
                if (protParam instanceof PivKeyStoreKeyParameters) {
                    pinPolicy = ((PivKeyStoreKeyParameters) protParam).pinPolicy;
                    touchPolicy = ((PivKeyStoreKeyParameters) protParam).touchPolicy;
                } else {
                    throw new KeyStoreException("protParam must be an instance of PivKeyStoreKeyParameters");
                }
            }
            try {
                piv.putKey(slot, ((KeyStore.PrivateKeyEntry) entry).getPrivateKey(), pinPolicy, touchPolicy);
            } catch (IOException | ApduException e) {
                throw new KeyStoreException(e);
            }
        }

        if (certificate != null) {
            try {
                piv.putCertificate(slot, (X509Certificate) certificate);
            } catch (IOException | ApduException e) {
                throw new KeyStoreException(e);
            }
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        Objects.requireNonNull(piv);
        Slot slot = parseAlias(alias);

        if (password != null) {
            throw new KeyStoreException("Password can not be set");
        }

        if (chain.length != 1) {
            throw new KeyStoreException("Certificate chain must be a single certificate, or empty");
        }
        if (chain[0] instanceof X509Certificate) {
            try {
                piv.putKey(slot, (PrivateKey) key, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);
                piv.putCertificate(slot, (X509Certificate) chain[0]);
            } catch (IOException | ApduException e) {
                throw new KeyStoreException(e);
            }
        } else {
            throw new KeyStoreException("Certificate must be X509Certificate");
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("Use setKeyEntry with a PrivateKey instance instead of byte[]");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        Objects.requireNonNull(piv);
        Slot slot = parseAlias(alias);
        if (cert instanceof X509Certificate) {
            try {
                piv.putCertificate(slot, (X509Certificate) cert);
            } catch (IOException | ApduException e) {
                throw new KeyStoreException(e);
            }
        } else {
            throw new KeyStoreException("Certificate must be X509Certificate");
        }
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        Objects.requireNonNull(piv);
        Slot slot = parseAlias(alias);
        try {
            piv.deleteCertificate(slot);
        } catch (IOException | ApduException e) {
            throw new KeyStoreException(e);
        }
    }

    @Override
    public Enumeration<String> engineAliases() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        try {
            parseAlias(alias);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public int engineSize() {
        return Slot.values().length;
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return engineContainsAlias(alias);
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        Objects.requireNonNull(piv);
        Slot slot = parseAlias(alias);
        try {
            piv.getCertificate(slot);
            return true;
        } catch (BadResponseException e) {
            return false;
        } catch (ApduException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    @Nullable
    public String engineGetCertificateAlias(Certificate cert) {
        Objects.requireNonNull(piv);
        for (Slot slot : Slot.values()) {
            X509Certificate entry;
            try {
                entry = piv.getCertificate(slot);
            } catch (IOException e) {
                return null;
            } catch (ApduException | BadResponseException e) {
                continue;
            }
            if (entry.equals(cert)) {
                return Integer.toString(slot.value, 16);
            }
        }
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) {
        throw new InvalidParameterException("KeyStore must be loaded with a PivLoadStoreParameter");
    }

    @Override
    public void engineLoad(KeyStore.LoadStoreParameter param) {
        if (param instanceof PivLoadStoreParameter) {
            piv = ((PivLoadStoreParameter) param).piv;
        } else {
            throw new InvalidParameterException("KeyStore must be loaded with a PivLoadStoreParameter");
        }
    }

    static Slot parseAlias(String alias) {
        try {
            return Slot.fromValue(Integer.parseInt(alias, 16));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(e);
        }
    }
}

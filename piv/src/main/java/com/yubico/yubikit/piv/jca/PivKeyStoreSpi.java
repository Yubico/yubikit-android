package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import javax.annotation.Nullable;

public class PivKeyStoreSpi extends KeyStoreSpi {
    private final Callback<Callback<Result<PivSession, Exception>>> provider;

    PivKeyStoreSpi(Callback<Callback<Result<PivSession, Exception>>> provider) {
        this.provider = provider;
    }

    private KeyType putKey(Slot slot, PrivateKey key, PinPolicy pinPolicy, TouchPolicy touchPolicy) throws Exception {
        CompletableFuture<Result<KeyType, Exception>> future = new CompletableFuture<>();
        provider.invoke(result -> future.complete(Result.of(() -> result.getValue().putKey(slot, key, pinPolicy, touchPolicy))));
        return future.get().getValue();
    }

    private void putCertificate(Slot slot, X509Certificate certificate) throws Exception {
        CompletableFuture<Result<Boolean, Exception>> future = new CompletableFuture<>();
        provider.invoke(result -> future.complete(Result.of(() -> {
            result.getValue().putCertificate(slot, certificate);
            return true;
        })));
        future.get().getValue();
    }

    private X509Certificate getCertificate(Slot slot) throws Exception {
        CompletableFuture<Result<X509Certificate, Exception>> future = new CompletableFuture<>();
        provider.invoke(result -> future.complete(Result.of(() -> result.getValue().getCertificate(slot))));
        return future.get().getValue();
    }

    private void deleteCertificate(Slot slot) throws Exception {
        CompletableFuture<Result<Boolean, Exception>> future = new CompletableFuture<>();
        provider.invoke(result -> future.complete(Result.of(() -> {
            result.getValue().deleteCertificate(slot);
            return true;
        })));
        future.get().getValue();
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
        Slot slot = parseAlias(alias);
        try {
            CompletableFuture<Result<PublicKey, Exception>> future = new CompletableFuture<>();
            provider.invoke(result -> future.complete(Result.of(() -> {
                PivSession session = result.getValue();
                if (session.supports(PivSession.FEATURE_METADATA)) {
                    return session.getSlotMetadata(slot).getPublicKey();
                } else {
                    return session.getCertificate(slot).getPublicKey();
                }
            })));
            PublicKey publicKey = future.get().getValue();
            return PivPrivateKey.from(publicKey, slot, password);
        } catch (BadResponseException e) {
            throw new UnrecoverableKeyException("No way to infer KeyType, make sure the matching certificate is stored");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        return new Certificate[]{engineGetCertificate(alias)};
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        Slot slot = parseAlias(alias);
        try {
            return getCertificate(slot);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    @Nullable
    public Date engineGetCreationDate(String alias) {
        return null;
    }

    @Override
    public void engineSetEntry(String alias, KeyStore.Entry entry, @Nullable KeyStore.ProtectionParameter protParam) throws KeyStoreException {
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
                putKey(slot, ((KeyStore.PrivateKeyEntry) entry).getPrivateKey(), pinPolicy, touchPolicy);
            } catch (Exception e) {
                throw new KeyStoreException(e);
            }
        }

        if (certificate != null) {
            try {
                putCertificate(slot, (X509Certificate) certificate);
            } catch (Exception e) {
                throw new KeyStoreException(e);
            }
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, @Nullable char[] password, Certificate[] chain) throws KeyStoreException {
        Objects.requireNonNull(provider);
        Slot slot = parseAlias(alias);

        if (password != null) {
            throw new KeyStoreException("Password can not be set");
        }

        if (chain.length != 1) {
            throw new KeyStoreException("Certificate chain must be a single certificate, or empty");
        }
        if (chain[0] instanceof X509Certificate) {
            try {
                putKey(slot, (PrivateKey) key, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);
                putCertificate(slot, (X509Certificate) chain[0]);
            } catch (Exception e) {
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
        Slot slot = parseAlias(alias);
        if (cert instanceof X509Certificate) {
            try {
                putCertificate(slot, (X509Certificate) cert);
            } catch (Exception e) {
                throw new KeyStoreException(e);
            }
        } else {
            throw new KeyStoreException("Certificate must be X509Certificate");
        }
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        Objects.requireNonNull(provider);
        Slot slot = parseAlias(alias);
        try {
            deleteCertificate(slot);
        } catch (Exception e) {
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
        Objects.requireNonNull(provider);
        Slot slot = parseAlias(alias);
        try {
            getCertificate(slot);
            return true;
        } catch (BadResponseException e) {
            return false;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    @Nullable
    public String engineGetCertificateAlias(Certificate cert) {
        Objects.requireNonNull(provider);
        for (Slot slot : Slot.values()) {
            X509Certificate entry;
            try {
                entry = getCertificate(slot);
            } catch (ApduException | BadResponseException e) {
                continue;
            } catch (Exception e) {
                return null;
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
        throw new InvalidParameterException("KeyStore must be loaded with a null LoadStoreParameter");
    }

    @Override
    public void engineLoad(@Nullable KeyStore.LoadStoreParameter param) {
        if (param != null) {
            throw new InvalidParameterException("KeyStore must be loaded with null");
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

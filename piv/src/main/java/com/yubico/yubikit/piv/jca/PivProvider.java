package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.crypto.NoSuchPaddingException;

public class PivProvider extends Provider {
    private static final Map<String, String> ecAttributes = Collections.singletonMap("SupportedKeyClasses", PivPrivateKey.EcKey.class.getName());
    private static final Map<String, String> rsaAttributes = Collections.singletonMap("SupportedKeyClasses", PivPrivateKey.RsaKey.class.getName());

    private final Callback<Callback<Result<PivSession, Exception>>> sessionRequester;
    private final Map<KeyType, KeyPair> rsaDummyKeys = new HashMap<>();

    /**
     * Creates a Security Provider wrapping an instance of a PivSession.
     * <p>
     * The PivSession must be active for as long as the Provider will be used.
     *
     * @param session A PivSession to use for YubiKey interaction.
     */
    public PivProvider(PivSession session) {
        this(callback -> callback.invoke(Result.success(session)));
    }

    /**
     * Creates a Security Provider capable of using a PivSession with a YubiKey to perform key operations.
     * @param sessionRequester a mechanism for the Provider to get an instance of a PivSession.
     */
    public PivProvider(Callback<Callback<Result<PivSession, Exception>>> sessionRequester) {
        super("YKPiv", 1.0, "JCA Provider for YubiKey PIV");
        this.sessionRequester = sessionRequester;

        Logger.d("EC " + ecAttributes);
        Logger.d("RSA " + rsaAttributes);

        putService(new Service(this, "Signature", "NONEwithECDSA", PivEcSignatureSpi.Prehashed.class.getName(), null, ecAttributes) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PivEcSignatureSpi.Prehashed(sessionRequester);
            }
        });

        try {
            KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
            long start = System.currentTimeMillis();
            for (KeyType keyType : new KeyType[]{KeyType.RSA1024, KeyType.RSA2048}) {
                //TODO: import static keys to avoid slow generation?
                rsaGen.initialize(keyType.params.bitLength);
                rsaDummyKeys.put(keyType, rsaGen.generateKeyPair());
            }
            long end = System.currentTimeMillis();
            Logger.d("TIME TAKEN: " + (end - start));

            putService(new PivRsaCipherService());
            putService(new PivRsaSignatureService("RSASSA-PSS"));
        } catch (NoSuchAlgorithmException e) {
            Logger.e("Unable to support RSA, no underlying Provider with RSA capability", e);
        }

        Set<String> digests = Security.getAlgorithms("MessageDigest");
        for (String signature : Security.getAlgorithms("Signature")) {
            if (signature.endsWith("WITHECDSA")) {
                String digest = signature.substring(0, signature.length() - 9);
                if (!digests.contains(digest)) {
                    // SHA names don't quite match between Signature and MessageDigest.
                    digest = digest.replace("SHA", "SHA-");
                    if (digest.equals("SHA-1")) {
                        digest = "SHA";
                    }
                }
                if (digests.contains(digest)) {
                    putService(new PivEcSignatureService(signature, digest));
                }
            } else if (!rsaDummyKeys.isEmpty() && signature.endsWith("WITHRSA")) {
                putService(new PivRsaSignatureService(signature));
            }
        }

        putService(new Service(this, "KeyPairGenerator", "RSA", PivKeyPairGeneratorSpi.Rsa.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PivKeyPairGeneratorSpi.Rsa(sessionRequester);
            }
        });
        putService(new Service(this, "KeyPairGenerator", "EC", PivKeyPairGeneratorSpi.Ec.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PivKeyPairGeneratorSpi.Ec(sessionRequester);
            }
        });
        putService(new Service(this, "KeyStore", "YKPiv", PivKeyStoreSpi.class.getName(), null, null) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PivKeyStoreSpi(sessionRequester);
            }
        });


        putService(new Service(this, "KeyAgreement", "ECDH", PivKeyAgreementSpi.class.getName(), null, ecAttributes) {
            @Override
            public Object newInstance(Object constructorParameter) {
                return new PivKeyAgreementSpi(sessionRequester);
            }
        });
    }

    @Override
    public synchronized boolean equals(Object o) {
        return o instanceof PivProvider && super.equals(o);
    }

    @Override
    public synchronized int hashCode() {
        return super.hashCode();
    }

    private class PivEcSignatureService extends Service {
        private final String digest;

        public PivEcSignatureService(String algorithm, String digest) {
            super(PivProvider.this, "Signature", algorithm, PivEcSignatureSpi.Hashed.class.getName(), null, ecAttributes);
            this.digest = digest;
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            return new PivEcSignatureSpi.Hashed(sessionRequester, digest);
        }
    }

    private class PivRsaSignatureService extends Service {
        public PivRsaSignatureService(String algorithm) {
            super(PivProvider.this, "Signature", algorithm, PivRsaSignatureSpi.class.getName(), null, rsaAttributes);
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            try {
                return new PivRsaSignatureSpi(sessionRequester, rsaDummyKeys, getAlgorithm());
            } catch (NoSuchPaddingException e) {
                throw new NoSuchAlgorithmException("No underlying Provider supporting " + getAlgorithm() + " available.");
            }
        }
    }

    private class PivRsaCipherService extends Service {
        public PivRsaCipherService() {
            super(PivProvider.this, "Cipher", "RSA", PivCipherSpi.class.getName(), null, rsaAttributes);
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            try {
                return new PivCipherSpi(sessionRequester, rsaDummyKeys);
            } catch (NoSuchPaddingException e) {
                throw new NoSuchAlgorithmException(e);
            }
        }
    }
}

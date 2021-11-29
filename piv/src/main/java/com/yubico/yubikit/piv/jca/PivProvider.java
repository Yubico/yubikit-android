package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.piv.KeyType;

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

    private final Map<KeyType, KeyPair> rsaDummyKeys = new HashMap<>();

    public PivProvider() {
        super("YKPiv", 1.0, "JCA Provider for YubiKey PIV");

        Logger.d("EC " + ecAttributes);
        Logger.d("RSA " + rsaAttributes);

        putService(new Service(this, "Signature", "NONEwithECDSA", PivEcSignatureSpi.Prehashed.class.getName(), null, ecAttributes));

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

        putService(new Service(this, "KeyPairGenerator", "RSA", PivKeyPairGeneratorSpi.Rsa.class.getName(), null, null));
        putService(new Service(this, "KeyPairGenerator", "EC", PivKeyPairGeneratorSpi.Ec.class.getName(), null, null));
        putService(new Service(this, "KeyStore", "YKPiv", PivKeyStoreSpi.class.getName(), null, null));


        putService(new Service(this, "KeyAgreement", "ECDH", PivKeyAgreementSpi.class.getName(), null, ecAttributes));
        putService(new Service(this, "KeyManagerFactory", "X509", PivKeyManagerFactorySpi.class.getName(), null, null));
    }

    private class PivEcSignatureService extends Service {
        private final String digest;

        public PivEcSignatureService(String algorithm, String digest) {
            super(PivProvider.this, "Signature", algorithm, PivEcSignatureSpi.Hashed.class.getName(), null, ecAttributes);
            this.digest = digest;
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            return new PivEcSignatureSpi.Hashed(digest);
        }
    }

    private class PivRsaSignatureService extends Service {
        public PivRsaSignatureService(String algorithm) {
            super(PivProvider.this, "Signature", algorithm, PivRsaSignatureSpi.class.getName(), null, rsaAttributes);
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            try {
                return new PivRsaSignatureSpi(rsaDummyKeys, getAlgorithm());
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
                return new PivCipherSpi(rsaDummyKeys);
            } catch (NoSuchPaddingException e) {
                throw new NoSuchAlgorithmException(e);
            }
        }
    }
}

package com.yubico.yubikit.piv.jca;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.util.Collections;
import java.util.Map;

public class PivProvider extends Provider {
    private static final Map<String, String> attributes = Collections.singletonMap("SupportedKeyClasses", PivPrivateKey.class.getName());

    public PivProvider() {
        super("YKPiv", 1.0, "JCA Provider for YubiKey PIV");

        putService(new PivSignatureService("NONEwithECDSA"));
        putService(new PivSignatureService("SHA1withECDSA"));
        putService(new PivSignatureService("SHA256withECDSA"));
        putService(new PivSignatureService("SHA384withECDSA"));
        putService(new PivSignatureService("SHA512withECDSA"));

        putService(new PivSignatureService("NONEwithRSA"));
        putService(new PivSignatureService("MD5withRSA"));
        putService(new PivSignatureService("SHA1withRSA"));
        putService(new PivSignatureService("SHA256withRSA"));
        putService(new PivSignatureService("SHA384withRSA"));
        putService(new PivSignatureService("SHA512withRSA"));
        putService(new PivSignatureService("RSASSA-PSS"));

        putService(new Service(this, "Cipher", "RSA", PivCipherSpi.class.getName(), null, attributes));
        putService(new Service(this, "KeyAgreement", "ECDH", PivKeyAgreementSpi.class.getName(), null, attributes));
        putService(new Service(this, "KeyManagerFactory", "X509", PivKeyManagerFactorySpi.class.getName(), null, null));
    }

    private class PivSignatureService extends Service {
        public PivSignatureService(String algorithm) {
            super(PivProvider.this, "Signature", algorithm, PivSignatureSpi.class.getName(), null, attributes);
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            return new PivSignatureSpi(Signature.getInstance(getAlgorithm()));
            /*
            for (Provider other : Security.getProviders()) {
                if (!other.getName().equals(getProvider().getName())) {
                    try {
                        return new PivSignatureSpi(Signature.getInstance(getAlgorithm(), other));
                    } catch (NoSuchAlgorithmException e) {
                        // Ignore, try next
                    }
                }
            }
            throw new NoSuchAlgorithmException("No underlying Provider supporting " + getAlgorithm() + " available.");
             */
        }
    }
}

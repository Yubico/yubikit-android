package com.yubico.yubikit.desktop.app;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.desktop.*;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.ManagementKeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.SlotMetadata;
import com.yubico.yubikit.piv.TouchPolicy;
import com.yubico.yubikit.piv.jca.PivAlgorithmParameterSpec;
import com.yubico.yubikit.piv.jca.PivKeyManager;
import com.yubico.yubikit.piv.jca.PivPrivateKey;
import com.yubico.yubikit.piv.jca.PivProvider;
import com.yubico.yubikit.testing.Codec;
import com.yubico.yubikit.testing.piv.PivTestUtils;
import com.yubico.yubikit.yubiotp.YubiOtpSession;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.Semaphore;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;

public class DesktopApp {
    public static void main(String[] argv) {
        if (OperatingSystem.isMac()) {
            System.setProperty("sun.security.smartcardio.library", "/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC");
        }

        System.out.println("Insert YubiKey now...");

        Logger.setLogger(new Logger() {
            @Override
            protected void logDebug(String message) {
                System.err.println("DEBUG: " + message);
            }

            @Override
            protected void logError(String message, Throwable throwable) {
                System.err.println("ERROR: " + message);
                throwable.printStackTrace();
            }
        });

        //testHidOtp();
        testCcid();

        Logger.d("Application exited");
    }

    private static void testCcid() {
        YubiKitManager yubikit = new YubiKitManager();

        yubikit.run(new PcscConfiguration(), new PcscSessionListener() {
            @Override
            public void onSessionReceived(PcscDevice session) {
                /*
                if (session.getInterface() == Interface.NFC) {
                    try {
                        byte[] ndefData = session.readNdef();
                        String otp = NdefUtils.getNdefPayload(ndefData);
                        Logger.d("Read OTP: " + otp);
                    } catch (IOException | ApduException | ApplicationNotAvailableException e) {
                        e.printStackTrace();
                    }
                }

                 */

                testPiv(session);

                try (PivSession piv = new PivSession(session.openIso7816Connection())) {
                    /*
                    PivJcaDeviceTests.testImportKeys(piv);
                    PivJcaDeviceTests.testGenerateKeys(piv);

                    PivDeviceTests.testSign(piv, KeyType.ECCP256);
                    PivDeviceTests.testSign(piv, KeyType.RSA2048);
                    PivDeviceTests.testDecrypt(piv, KeyType.RSA2048);
                     */

                    //testHttps(piv);

                    /*
                    for (Slot slot : Arrays.asList(Slot.AUTHENTICATION, Slot.SIGNATURE, Slot.CARD_AUTH, Slot.KEY_MANAGEMENT)) {
                        System.out.println("Slot: " + slot);
                        try {
                            System.out.println(piv.getCertificate(slot));
                        } catch (ApduException | BadResponseException e) {
                            System.out.println("No certificate");
                        }
                    }*/
                } catch (Exception e) {
                    e.printStackTrace();
                }

                yubikit.stop();
            }

            @Override
            public void onSessionRemoved(PcscDevice session) {
                Logger.d("Shutting down...");
                yubikit.stop();
            }
        });
    }

    private static void testHttps(PivSession piv) throws Exception {
        Security.addProvider(new PivProvider(piv));

        URL url = new URL("https://dain.se:8443");

        KeyStore keyStore = KeyStore.getInstance("YKPiv");
        keyStore.load(null);
        PivPrivateKey privateKey = (PivPrivateKey) keyStore.getKey("9a", "123456".toCharArray());

        X509Certificate certificate = (X509Certificate) keyStore.getCertificate("9a");
        //PivPrivateKey privateKey = PivPrivateKey.from(certificate.getPublicKey(), Slot.AUTHENTICATION, null);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(new KeyManager[]{new PivKeyManager(privateKey, new X509Certificate[]{certificate})}, null, null);

        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());

        piv.verifyPin("123456".toCharArray());

        try(BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
            reader.lines().forEach(Logger::d);
        }

        Security.removeProvider("YKPiv");
    }

    private static void testPiv(PcscDevice session) {
        try (PivSession piv = new PivSession(session.openIso7816Connection())) {
            //piv.authenticate(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8});
            //Logger.d("Generate key...");
            //piv.generateKey(Slot.SIGNATURE, KeyType.ECCP256, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);
            try {
                Logger.d("Get metadata...");
                SlotMetadata metadata = piv.getSlotMetadata(Slot.AUTHENTICATION);
                Logger.d("Metadata: " + metadata.getKeyType() + ", " + metadata.isGenerated() + ", " + metadata.getPinPolicy() + ", " + metadata.getPublicKey());

            } catch (UnsupportedOperationException e) {
                Logger.e("Metadata not supported", e);
            }
            piv.authenticate(ManagementKeyType.TDES, Codec.fromHex("010203040506070801020304050607080102030405060708"));

            Provider provider = new PivProvider(piv);
            Security.addProvider(provider);

            // Create certificate
            //Provider provider = new PivProvider(piv);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("YkPivEC", provider);
            kpg.initialize(new PivAlgorithmParameterSpec(Slot.AUTHENTICATION, KeyType.ECCP256, PinPolicy.ALWAYS, TouchPolicy.DEFAULT, "123456".toCharArray()));
            KeyPair keyPair = kpg.generateKeyPair();

            X509Certificate cert = PivTestUtils.createCertificate(keyPair);
            cert.verify(keyPair.getPublic());
            piv.putCertificate(Slot.AUTHENTICATION, cert);

            piv.getCertificate(Slot.AUTHENTICATION);

            //Logger.d("Metadata management: " + piv.getSlotMetadata(Slot.CARD_MANAGEMENT));

            //Logger.d("Metadata authentication: " + metadata.getKeyType() + ", " + metadata.isGenerated() + ", " + metadata.getPinPolicy() + ", " + metadata.getPublicKey());
            //metadata = piv.getSlotMetadata(Slot.SIGNATURE);


            /*
            PinMetadata pinMetadata = piv.getPinMetadata();
            Logger.d("PIN: default=" + pinMetadata.isDefaultValue() + ", total="+pinMetadata.getTotalAttempts()+", remaining="+pinMetadata.getAttemptsRemaining());

            PinMetadata pukMetadata = piv.getPukMetadata();
            Logger.d("PUK: default=" + pukMetadata.isDefaultValue() + ", total="+pukMetadata.getTotalAttempts()+", remaining="+pukMetadata.getAttemptsRemaining());
            PivDeviceTests.testDecrypt(piv, KeyType.RSA1024);
            PivDeviceTests.testDecrypt(piv, KeyType.RSA2048);
            PivDeviceTests.testEcdh(piv, KeyType.ECCP256);
            PivDeviceTests.testEcdh(piv, KeyType.ECCP384);

            piv.authenticate(Codec.fromHex("010203040506070801020304050607080102030405060708"));
            PublicKey pub = piv.generateKey(Slot.AUTHENTICATION, KeyType.ECCP256, PinPolicy.ALWAYS, TouchPolicy.DEFAULT);
            piv.verify("123456".toCharArray());
            X509Certificate cert = PivTestUtils.createCertificate(piv, pub, Slot.AUTHENTICATION, KeyType.ECCP256);
            cert.verify(pub);
            piv.putCertificate(Slot.AUTHENTICATION, cert);

            pub = piv.generateKey(Slot.AUTHENTICATION, KeyType.RSA1024, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);
            piv.verify("123456".toCharArray());
            cert = PivTestUtils.createCertificate(piv, pub, Slot.AUTHENTICATION, KeyType.RSA1024);
            cert.verify(pub);
            piv.putCertificate(Slot.AUTHENTICATION, cert);

                /*
                PivDeviceTests.testManagementKey(piv);
                PivDeviceTests.testPin(piv);
                PivDeviceTests.testPuk(piv);
                PivDeviceTests.testGenerateKeys(piv);
                PivDeviceTests.testImportKeys(piv);
                */
        } catch (RuntimeException e) {
            Logger.e("Error", e.getCause() != null ? e.getCause() : e);
        } catch (ApplicationNotAvailableException | ApduException | IOException e) {
            Logger.e("Error", e);
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (BadResponseException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        Logger.d("PIV tests done!");
    }

    private static void testHidOtp() {
        YubiKitHidManager hidManager = new YubiKitHidManager();

        Semaphore lock = new Semaphore(0);

        hidManager.setListener(new HidSessionListener() {
            @Override
            public void onSessionReceived(HidDevice device) {
                Logger.d("HID session started");
                YubiOtpSession.create(device, result -> {
                    try {
                        YubiOtpSession app = result.getValue();
                        Logger.d("HID read version: " + app.getVersion());

                        Logger.d("Slot 1: " + app.getConfigurationState().isConfigured(com.yubico.yubikit.yubiotp.Slot.ONE));
                        Logger.d("Slot 2: " + app.getConfigurationState().isConfigured(com.yubico.yubikit.yubiotp.Slot.TWO));
                        //app.setHmacSha1Key(com.yubico.yubikit.otp.Slot.TWO, new byte[]{1,2,3,4,5,6}, true);
                        //app.setStaticPassword(com.yubico.yubikit.otp.Slot.TWO, new byte[]{(byte) 0x8b, 0x0c});
                        app.swapConfigurations();
                        //app.deleteSlot(com.yubico.yubikit.otp.Slot.ONE, null);
                        Logger.d("Configuration updated");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    lock.release();
                });
            }

            @Override
            public void onSessionRemoved(HidDevice session) {
                lock.release();
            }
        });

        try {
            lock.acquire();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
package com.yubico.yubikit.testing.piv;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.jca.PivProvider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;
import java.util.Set;

public class PivJcaUtils {
    public static void setupJca(PivSession piv) {
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
        Security.insertProviderAt(new PivProvider(piv), 1);
        listJcaProviders();
    }

    public static void tearDownJca() {
        Security.removeProvider("YKPiv");
    }

    public static void listJcaProviders() {
        Provider[] providers = Security.getProviders();

        for (Provider p : providers) {
            @SuppressWarnings("deprecation")
            String providerInfo = p.getName() + "/" + p.getInfo() + "/" + p.getVersion();
            Logger.d(providerInfo);
            Set<Provider.Service> services = p.getServices();
            for (Provider.Service s : services) {
                String serviceInfo = p.getName() + ":" + s.getType() + "/" + s.getAlgorithm() + "/" + s.getClassName();
                Logger.d(serviceInfo);
            }
        }
    }
}

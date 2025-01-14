/*
 * Copyright (C) 2022-2023 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.testing.piv;

import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.jca.PivProvider;
import java.security.Provider;
import java.security.Security;
import java.util.Set;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PivJcaUtils {
  private static final Logger logger = LoggerFactory.getLogger(PivJcaUtils.class);

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
      double version = p.getVersion();
      logger.debug("{}/{}/{}", p.getName(), p.getInfo(), version);
      Set<Provider.Service> services = p.getServices();
      for (Provider.Service s : services) {
        logger.debug("\t{}: {} -> {}", s.getType(), s.getAlgorithm(), s.getClassName());
      }
    }
  }
}

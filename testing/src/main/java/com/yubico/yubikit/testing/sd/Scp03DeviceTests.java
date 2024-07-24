/*
 * Copyright (C) 2023 Yubico.
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

package com.yubico.yubikit.testing.sd;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.scp.KeyRef;
import com.yubico.yubikit.core.smartcard.scp.Scp03KeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;
import com.yubico.yubikit.core.smartcard.scp.StaticKeys;

import java.io.IOException;
import java.util.Map;

public class Scp03DeviceTests {

    public static void testImportScp03(SecurityDomainTestState state) throws Throwable {

        final byte[] sk = new byte[]{
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
        };
        final StaticKeys staticKeys = new StaticKeys(sk, sk, sk);

        // reset security domain to get default keys
        state.withSecurityDomain(SecurityDomainSession::reset);
        state.withSecurityDomain(sd -> {
            // this session is initialized
            KeyRef keyRef = getKeyRef(sd, ScpKid.SCP03);
            ScpKeyParams keyParams = new Scp03KeyParams(keyRef, StaticKeys.getDefaultKeys());
            sd.authenticate(keyParams);
            sd.putKey(keyRef, staticKeys, 0);
        });
    }

    private static KeyRef getKeyRef(SecurityDomainSession scp, byte kid)
            throws ApduException, IOException, BadResponseException {
        Map<KeyRef, Map<Byte, Byte>> keyInformation = scp.getKeyInformation();
        KeyRef keyRef = null;
        for (KeyRef info : keyInformation.keySet()) {
            if (info.getKid() == kid) {
                keyRef = info;
                break;
            }
        }
        return keyRef;
    }
}

/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.testing;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.scp.KeyRef;
import com.yubico.yubikit.core.smartcard.scp.Scp11KeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

public class TestState {
    public static ScpKeyParams keyParams = null;

    public static ScpKeyParams readScpKeyParams(YubiKeyDevice device, @Nullable Byte kid) throws Throwable {
        if (kid == null) {
            return null;
        }
        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            SecurityDomainSession scp = new SecurityDomainSession(connection);
            KeyRef keyRef = getKeyRef(scp, kid);
            List<X509Certificate> certs = scp.getCertificateBundle(keyRef);

            return certs.isEmpty()
                    ? null
                    : kid == ScpKid.SCP03
                    ? null // TODO implement SCP03 support
                    : new Scp11KeyParams(keyRef, certs.get(certs.size() - 1).getPublicKey());
        }
    }

    private static KeyRef getKeyRef(SecurityDomainSession scp, byte kid) throws ApduException, IOException, BadResponseException {
        Map<KeyRef, Map<Byte, Byte>> keyInformation = scp.getKeyInformation();
        KeyRef keyRef = null;
        for (KeyRef info : keyInformation.keySet()) {
            if (info.getKid() == kid) {
                keyRef = info;
                break;
            }
        }

        if (keyRef == null) {
            throw new IllegalStateException("Failed to find required key");
        }
        return keyRef;
    }
}

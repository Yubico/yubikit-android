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

package com.yubico.yubikit.testing.sd;

import static org.junit.Assert.assertNull;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;
import com.yubico.yubikit.testing.TestState;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class SecurityDomainTestState extends TestState {

    public static class Builder extends TestState.Builder<SecurityDomainTestState.Builder> {

        public Builder(YubiKeyDevice device) {
            super(device);
        }

        public SecurityDomainTestState build() throws Throwable {
            return new SecurityDomainTestState(this);
        }
    }

    protected SecurityDomainTestState(Builder builder) throws Throwable {
        super(builder);

        setupJca();

        try (SmartCardConnection connection = openSmartCardConnection()) {
            assumeTrue("Key does not support smart card connection", connection != null);
            SecurityDomainSession sd = getSecurityDomainSession(connection);
            assumeTrue("Security domain not supported", sd != null);
            assertNull("These tests expect kid to be null", scpParameters.getKid());
        }

    }

    public static void setupJca() {
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
    }
}

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

package com.yubico.yubikit.testing.oath;

import javax.annotation.Nullable;

import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.testing.framework.OathInstrumentedTests;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        OathTests.NoScpTests.class,
        OathTests.Scp11bTests.class,
})
public class OathTests {
    public static class NoScpTests extends OathInstrumentedTests {
        @Test
        public void testChangePassword() throws Throwable {
            withOathSession(OathDeviceTests::testChangePassword);
            withOathSession(OathDeviceTests::testChangePasswordAfterReconnect);
        }

        @Test
        public void testResetPassword() throws Throwable {
            withOathSession(OathDeviceTests::testRemovePassword);
        }

        @Test
        public void testAccountManagement() throws Throwable {
            withOathSession(OathDeviceTests::testAccountManagement);
        }
    }

    public static class Scp11bTests extends NoScpTests {
        @Nullable
        @Override
        protected Byte getScpKid() {
            return ScpKid.SCP11b;
        }
    }
}

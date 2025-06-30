/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.testing.yubiotp;

import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.testing.SmokeTest;

import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import javax.annotation.Nullable;

import com.yubico.yubikit.testing.framework.YubiOtpInstrumentedTests;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        com.yubico.yubikit.testing.yubiotp.YubiOtpTests.NoScpTests.class,
        com.yubico.yubikit.testing.yubiotp.YubiOtpTests.Scp11bTests.class,
})
public class YubiOtpTests {

    public static class NoScpTests extends YubiOtpInstrumentedTests {
        @Test
        @Category(SmokeTest.class)
        public void testChangePassword() throws Throwable {
            withDevice(YubiOtpDeviceTests::testChangePassword);
        }

        @Test
        public void testResetPassword() throws Throwable {
            withYubiOtpSession(YubiOtpDeviceTests::testRemovePassword);
        }

        @Test
        @Category(SmokeTest.class)
        public void testAccountManagement() throws Throwable {
            withYubiOtpSession(YubiOtpDeviceTests::testAccountManagement);
        }

        @Test
        public void testRenameAccount() throws Throwable {
            withYubiOtpSession(YubiOtpDeviceTests::testRenameAccount);
        }
    }

    public static class Scp11bTests extends com.yubico.yubikit.testing.yubiotp.YubiOtpTests.NoScpTests {
        @Nullable
        @Override
        protected Byte getScpKid() {
            return ScpKid.SCP11b;
        }
    }
}

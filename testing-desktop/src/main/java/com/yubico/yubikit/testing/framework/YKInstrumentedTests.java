/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.testing.framework;

import com.yubico.yubikit.core.YubiKeyDevice;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.ExternalResource;
import org.junit.rules.TestName;
import org.junit.rules.TestRule;

import com.yubico.yubikit.testing.DesktopTestDriver;

public class YKInstrumentedTests {

    protected YubiKeyDevice device = null;
    private final DesktopTestDriver testDriver = new DesktopTestDriver();

    @Rule
    public final TestName name = new TestName();

    @Rule
    public final ExternalResource externalResource = new ExternalResource() {

        @Override
        protected void before() throws Throwable {
            device = testDriver.awaitSession();
            System.out.println("Got session");
        }

        @Override
        protected void after() {
            System.out.println("Returning session");
            testDriver.returnSession(device);
            device = null;
        }
    };

}

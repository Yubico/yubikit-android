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

import androidx.test.rule.ActivityTestRule;

import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.testing.TestActivity;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestName;

public class YKInstrumentedTests {

    protected YubiKeyDevice device = null;

    @Rule
    public final TestName name = new TestName();

    @Rule
    public final ActivityTestRule<TestActivity> rule = new ActivityTestRule<>(TestActivity.class);

    @Before
    public void getYubiKey() throws InterruptedException {
        device = rule.getActivity().awaitSession(
                getClass().getSimpleName() + " / " + name.getMethodName()
        );
    }

    @After
    public void releaseYubiKey() throws InterruptedException {
        rule.getActivity().returnSession(device);
        device = null;
    }
}

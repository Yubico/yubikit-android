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

package com.yubico.yubikit.testing.framework;

import androidx.test.ext.junit.rules.ActivityScenarioRule;

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
    public final ActivityScenarioRule<TestActivity> scenarioRule = new ActivityScenarioRule<>(TestActivity.class);

    @Before
    public void getYubiKey() {
        scenarioRule.getScenario().onActivity(action -> {
            try {
                device = action.awaitSession(getClass().getSimpleName(), name.getMethodName());
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        });
    }

    @After
    public void releaseYubiKey() {
        scenarioRule.getScenario().onActivity(action -> {
            try {
                action.returnSession(device);
                device = null;
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        });
    }
}


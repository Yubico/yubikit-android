/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * Instrumented tests that need no YubiKey, and so can run unattended.
 *
 * <p>Kept out of {@link DeviceTests} on purpose. Every member of that suite blocks in {@code
 * TestActivity.awaitSession} waiting for a key, so mixing these in would tie them to a hardware run
 * - and an early attempt to do so wedged the hardware tests that followed. Running them on every
 * push is a job for CI, which needs no key and cannot forget.
 *
 * <p>Add a test here only if it needs no YubiKey. Keep the suite non-empty: a suite with no classes
 * reports zero tests and still passes, which is the silent success this harness exists to avoid.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
  ThemeInflationTests.class,
  LoggingSmokeTests.class,
  GuardedLoggingCallSitesTest.class
})
public class KeylessDeviceTests {}

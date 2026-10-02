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

import com.yubico.yubikit.core.ExternalCcidReaderTests;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * Instrumented tests that need a third-party USB smart card reader on the Android device, not a
 * directly attached YubiKey. See {@link ExternalCcidReaderTests} for the hardware setup.
 *
 * <p>Kept out of {@link DeviceTests} because that suite's hardware is a YubiKey in the phone's USB
 * port or on its NFC antenna, which is a different rig. Run this one on its own:
 *
 * <pre>{@code
 * ./gradlew :testing-android:connectedAndroidTest \
 *   -Pandroid.testInstrumentationRunnerArguments.class=com.yubico.yubikit.ExternalReaderTests
 * }</pre>
 *
 * <p>Members must fail, not skip, when the expected reader is absent. A suite of skipped tests
 * reports green and reads as coverage that was never exercised.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ExternalCcidReaderTests.class})
public class ExternalReaderTests {}

/*
 * Copyright (C) 2024-2025 Yubico.
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

import org.junit.experimental.categories.Categories;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * A quick check that every application and transport still works, about a minute of test time over
 * USB. One or two tests per application (management, PIV, OATH, OpenPGP, YubiOTP, Security Domain,
 * FIDO over HID/NFC and over CCID), APDU framing, and cancellation for CTAP1 and CTAP2.
 *
 * <p>Excluded are the {@link PinUvAuthProtocolV1Test} variants, which repeat the PIN/UV protocol 2
 * tests, {@link SlowTest} and {@link AlwaysManualTest}. No test waits for a touch, so the set also
 * runs over NFC, where the cancellation tests skip.
 *
 * <p>The YubiKey applications will be modified: PINs, management keys, credentials and Security
 * Domain keys are changed. Use a designated test key.
 *
 * <p>More thorough sets are {@link FastDeviceTests} and {@link DeviceTests}.
 */
@RunWith(Categories.class)
@Categories.IncludeCategory(SmokeTest.class)
@Categories.ExcludeCategory({PinUvAuthProtocolV1Test.class, SlowTest.class, AlwaysManualTest.class})
@Suite.SuiteClasses(DeviceTests.class)
public class SmokeDeviceTests {}

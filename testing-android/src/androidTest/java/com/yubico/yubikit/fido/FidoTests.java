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

package com.yubico.yubikit.fido;

import com.yubico.yubikit.AlwaysManualTest;
import com.yubico.yubikit.fido.client.Ctap1ClientInstrumentedTests;
import com.yubico.yubikit.fido.client.Ctap2ClientInstrumentedTests;
import com.yubico.yubikit.fido.client.Ctap2ClientPinInstrumentedTests;
import com.yubico.yubikit.fido.client.UvDiscouragedInstrumentedTests;
import com.yubico.yubikit.fido.client.extensions.ExtensionsInstrumentedTests;
import com.yubico.yubikit.fido.ctap.Ctap2BioEnrollmentInstrumentedTests;
import com.yubico.yubikit.fido.ctap.Ctap2ConfigInstrumentedTests;
import com.yubico.yubikit.fido.ctap.Ctap2CredentialManagementInstrumentedTests;
import com.yubico.yubikit.fido.ctap.Ctap2SessionInstrumentedTests;
import com.yubico.yubikit.fido.ctap.Ctap2SessionResetInstrumentedTests;
import org.junit.experimental.categories.Categories;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * Setup YubiKey before running the integration tests:
 *
 * <ul>
 *   <li>reset the FIDO application
 *   <li>optionally set PIN to `11234567`
 * </ul>
 */
@RunWith(Categories.class)
@Suite.SuiteClasses({
  Ctap1ClientInstrumentedTests.class,
  Ctap2ClientInstrumentedTests.class,
  Ctap2ClientPinInstrumentedTests.class,
  Ctap2CredentialManagementInstrumentedTests.class,
  Ctap2SessionInstrumentedTests.class,
  EnterpriseAttestationInstrumentedTests.class,
  UvDiscouragedInstrumentedTests.class,
  Ctap2ConfigInstrumentedTests.class,
  Ctap2BioEnrollmentInstrumentedTests.class,
  Ctap2SessionResetInstrumentedTests.class,
  ExtensionsInstrumentedTests.class,
})
@Categories.ExcludeCategory(AlwaysManualTest.class)
public class FidoTests {}

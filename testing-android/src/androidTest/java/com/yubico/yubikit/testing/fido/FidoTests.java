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

package com.yubico.yubikit.testing.fido;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        BasicWebAuthnClientInstrumentedTests.class,
        Ctap2BioEnrollmentInstrumentedTests.class,
        Ctap2ClientPinInstrumentedTests.class,
        Ctap2ConfigInstrumentedTests.class,
        Ctap2CredentialManagementInstrumentedTests.class,
        Ctap2SessionInstrumentedTests.class,
        Ctap2SessionResetInstrumentedTests.class,
        EnterpriseAttestationInstrumentedTests.class,
        UvDiscouragedInstrumentedTests.class,
})
public class FidoTests {
}

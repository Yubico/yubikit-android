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

package com.yubico.yubikit.testing;

import com.yubico.yubikit.testing.mpe.MultiProtocolResetTests;
import com.yubico.yubikit.testing.fido.FidoTests;
import com.yubico.yubikit.testing.oath.OathTests;
import com.yubico.yubikit.testing.openpgp.OpenPgpTests;
import com.yubico.yubikit.testing.piv.PivTests;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * All integration tests for PIV, OpenPGP and OATH.
 * <p>
 * The YubiKey applications will be reset several times.
 * <p>
 * FIDO integration tests cannot be ran in this suite and can be found in
 * {@link com.yubico.yubikit.testing.fido.FidoTests}
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
        PivTests.class,
        OpenPgpTests.class,
        OathTests.class,
        MultiProtocolResetTests.class,
        FidoTests.class
})
public class DeviceTests {
}

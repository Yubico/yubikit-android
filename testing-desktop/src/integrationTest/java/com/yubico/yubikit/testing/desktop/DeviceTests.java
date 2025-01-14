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

package com.yubico.yubikit.testing.desktop;

import com.yubico.yubikit.testing.desktop.fido.FidoTests;
import com.yubico.yubikit.testing.desktop.mpe.MultiProtocolResetTests;
import com.yubico.yubikit.testing.desktop.oath.OathTests;
import com.yubico.yubikit.testing.desktop.openpgp.OpenPgpTests;
import com.yubico.yubikit.testing.desktop.piv.PivTests;
import com.yubico.yubikit.testing.desktop.sd.SecurityDomainTests;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * All integration tests for Security domain, PIV, OpenPGP, OATH, FIDO2 and MPE.
 *
 * <p>The YubiKey applications will be reset several times.
 *
 * <p>
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
  SecurityDomainTests.class,
  PivTests.class,
  OpenPgpTests.class,
  OathTests.class,
  MultiProtocolResetTests.class,
  FidoTests.class
})
public class DeviceTests {}

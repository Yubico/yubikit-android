/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.testing.neo;

import static org.hamcrest.Matchers.is;

import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.ManagementSession;
import org.junit.Assume;

public class NeoDeviceTests {
  public static void testOpenManagementSession(SmartCardConnection connection) throws Exception {
    ManagementSession session = new ManagementSession(connection);
    int major = session.getVersion().major;
    Assume.assumeThat(3, is(major));
  }
}

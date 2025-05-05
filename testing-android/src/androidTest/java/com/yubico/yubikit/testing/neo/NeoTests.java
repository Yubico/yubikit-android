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

import com.yubico.yubikit.testing.AlwaysManualTest;
import com.yubico.yubikit.testing.framework.NeoInstrumentedTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class NeoTests extends NeoInstrumentedTests {

  /**
   * Test that the management session can be opened on NEO
   *
   * <p>Run this test with over USB and NFC
   *
   * <p>Will be marked as skipped if the device is not a NEO
   */
  @Test
  @Category(AlwaysManualTest.class)
  public void testOpenManagementSession() throws Throwable {
    withConnection(NeoDeviceTests::testOpenManagementSession);
  }
}

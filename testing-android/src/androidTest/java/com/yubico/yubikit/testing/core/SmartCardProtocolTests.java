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

package com.yubico.yubikit.testing.core;

import com.yubico.yubikit.testing.SmokeTest;
import com.yubico.yubikit.testing.framework.CoreInstrumentedTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class SmartCardProtocolTests extends CoreInstrumentedTests {
  @Test
  @Category(SmokeTest.class)
  public void testApduSizesOverScp() throws Throwable {
    withState(SmartCardProtocolDeviceTests::testApduSizesOverScp);
  }

  @Test
  @Category(SmokeTest.class)
  public void testApduSizes() throws Throwable {
    withState(SmartCardProtocolDeviceTests::testApduSizes);
  }
}

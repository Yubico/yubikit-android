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

package com.yubico.yubikit.testing.sd;

import com.yubico.yubikit.testing.SmokeTest;
import com.yubico.yubikit.testing.framework.SecurityDomainInstrumentedTests;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class Scp03Tests extends SecurityDomainInstrumentedTests {

  @Before
  public void before() throws Throwable {
    withState(Scp03DeviceTests::before);
  }

  @Test
  public void testImportKey() throws Throwable {
    withState(Scp03DeviceTests::testImportKey);
  }

  @Test
  public void testDeleteKey() throws Throwable {
    withState(Scp03DeviceTests::testDeleteKey);
  }

  @Test
  @Category(SmokeTest.class)
  public void testReplaceKey() throws Throwable {
    withState(Scp03DeviceTests::testReplaceKey);
  }

  @Test
  public void testWrongKey() throws Throwable {
    withState(Scp03DeviceTests::testWrongKey);
  }
}

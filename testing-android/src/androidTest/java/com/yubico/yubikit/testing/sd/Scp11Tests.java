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

package com.yubico.yubikit.testing.sd;

import com.yubico.yubikit.testing.framework.SecurityDomainInstrumentedTests;
import org.junit.Before;
import org.junit.Test;

public class Scp11Tests extends SecurityDomainInstrumentedTests {

  @Before
  public void before() throws Throwable {
    withState(Scp11DeviceTests::before);
  }

  @Test
  public void testScp11aAuthenticate() throws Throwable {
    withState(Scp11DeviceTests::testScp11aAuthenticate);
  }

  @Test
  public void testScp11aAllowlist() throws Throwable {
    withState(Scp11DeviceTests::testScp11aAllowList);
  }

  @Test
  public void testScp11aAllowlistBlocked() throws Throwable {
    withState(Scp11DeviceTests::testScp11aAllowListBlocked);
  }

  @Test
  public void testScp11bAuthenticate() throws Throwable {
    withState(Scp11DeviceTests::testScp11bAuthenticate);
  }

  @Test
  public void testScp11bWrongPubKey() throws Throwable {
    withState(Scp11DeviceTests::testScp11bWrongPubKey);
  }

  @Test
  public void testScp11bImport() throws Throwable {
    withState(Scp11DeviceTests::testScp11bImport);
  }

  @Test
  public void testScp11cAuthenticate() throws Throwable {
    withState(Scp11DeviceTests::testScp11cAuthenticate);
  }
}

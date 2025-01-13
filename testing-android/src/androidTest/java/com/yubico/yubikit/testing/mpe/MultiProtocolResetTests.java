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

package com.yubico.yubikit.testing.mpe;

import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.testing.framework.MpeInstrumentedTests;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  MultiProtocolResetTests.NoScpTests.class,
  MultiProtocolResetTests.Scp11bTests.class,
})
public class MultiProtocolResetTests {
  public static class NoScpTests extends MpeInstrumentedTests {
    @Test
    public void testSettingPivPinBlocksFidoReset() throws Throwable {
      withPivSession(MultiProtocolResetDeviceTests::testSettingPivPinBlocksFidoReset);
    }

    @Test
    public void testPivOperationBlocksFidoReset() throws Throwable {
      withPivSession(MultiProtocolResetDeviceTests::testPivOperationBlocksFidoReset);
    }

    @Test
    public void testSettingFidoPinBlocksPivReset() throws Throwable {
      withCtap2Session(MultiProtocolResetDeviceTests::testSettingFidoPinBlocksPivReset);
    }
  }

  public static class Scp11bTests extends NoScpTests {
    @Nullable
    @Override
    protected Byte getScpKid() {
      return ScpKid.SCP11b;
    }
  }
}

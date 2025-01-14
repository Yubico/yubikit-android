/*
 * Copyright (C) 2022-2024 Yubico.
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

package com.yubico.yubikit.testing.piv;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.testing.SlowTest;
import com.yubico.yubikit.testing.SmokeTest;
import com.yubico.yubikit.testing.framework.PivInstrumentedTests;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class PivJcaProviderTests {

  public static class NoScpTests extends PivInstrumentedTests {
    @Test
    @Category(SlowTest.class)
    public void testGenerateKeys() throws Throwable {
      withPivSession(PivJcaDeviceTests::testGenerateKeys);
    }

    @Test
    @Category(SlowTest.class)
    public void testGenerateKeysPreferBC() throws Throwable {
      withPivSession(PivJcaDeviceTests::testGenerateKeysPreferBC);
    }

    @Test
    @Category(SmokeTest.class)
    public void testImportKeys() throws Throwable {
      withPivSession(PivJcaDeviceTests::testImportKeys);
    }

    @Test
    @Category(SlowTest.class)
    public void testSigning() throws Throwable {
      withPivSession(PivJcaSigningTests::testSign);
    }

    @Test
    @Category(SlowTest.class)
    public void testDecrypt() throws Throwable {
      withPivSession(PivJcaDecryptTests::testDecrypt);
    }

    @Test
    public void testMoveKey() throws Throwable {
      withPivSession(PivMoveKeyTests::moveKey);
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

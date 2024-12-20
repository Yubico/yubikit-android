/*
 * Copyright (C) 2022,2024 Yubico.
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

package com.yubico.yubikit.piv;

import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.piv.jca.PivProvider;
import com.yubico.yubikit.testing.piv.PivTestUtils;
import java.security.Security;
import org.junit.Test;

public class PivProviderTest {
  @Test
  public void testStandardAlgorithms() throws Exception {
    PivTestUtils.rsaTests();
    PivTestUtils.ecTests();
    PivTestUtils.cv25519Tests();
  }

  @Test
  public void testAlgorithmsWithProvider() throws Exception {
    // This doesn't actually use the provider, it makes sure the provider doesn't interfere.
    Security.insertProviderAt(
        new PivProvider(
            callback -> callback.invoke(Result.failure(new UnsupportedOperationException()))),
        1);

    PivTestUtils.rsaTests();
    PivTestUtils.ecTests();
    PivTestUtils.cv25519Tests();
  }
}

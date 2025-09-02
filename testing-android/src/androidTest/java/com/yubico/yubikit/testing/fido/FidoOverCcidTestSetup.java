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

package com.yubico.yubikit.testing.fido;

import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;
import java.util.Collections;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @noinspection NewClassNamingConvention
 */
public class FidoOverCcidTestSetup {
  @BeforeClass
  public static void setupCcidOnlyConnections() {
    FidoInstrumentedTests.connectionTypes = Collections.singletonList(SmartCardConnection.class);
  }

  @Test
  public void dummy() {}
}

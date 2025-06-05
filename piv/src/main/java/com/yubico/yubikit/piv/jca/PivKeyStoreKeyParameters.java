/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.TouchPolicy;
import java.security.KeyStore;

public class PivKeyStoreKeyParameters implements KeyStore.ProtectionParameter {
  final PinPolicy pinPolicy;
  final TouchPolicy touchPolicy;

  public PivKeyStoreKeyParameters(PinPolicy pinPolicy, TouchPolicy touchPolicy) {
    this.pinPolicy = pinPolicy;
    this.touchPolicy = touchPolicy;
  }
}

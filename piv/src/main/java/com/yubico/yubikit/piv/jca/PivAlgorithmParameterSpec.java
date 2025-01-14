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

import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.annotation.Nullable;
import javax.security.auth.Destroyable;

public class PivAlgorithmParameterSpec implements AlgorithmParameterSpec, Destroyable {
  final Slot slot;
  final KeyType keyType;
  final PinPolicy pinPolicy;
  final TouchPolicy touchPolicy;
  @Nullable final char[] pin;
  private boolean destroyed = false;

  public PivAlgorithmParameterSpec(
      Slot slot,
      KeyType keyType,
      @Nullable PinPolicy pinPolicy,
      @Nullable TouchPolicy touchPolicy,
      @Nullable char[] pin) {
    this.slot = slot;
    this.keyType = keyType;
    this.pinPolicy = pinPolicy != null ? pinPolicy : PinPolicy.DEFAULT;
    this.touchPolicy = touchPolicy != null ? touchPolicy : TouchPolicy.DEFAULT;
    this.pin = pin != null ? Arrays.copyOf(pin, pin.length) : null;
  }

  @Override
  public void destroy() {
    if (pin != null) {
      Arrays.fill(pin, (char) 0);
    }
    destroyed = true;
  }

  @Override
  public boolean isDestroyed() {
    return destroyed;
  }
}

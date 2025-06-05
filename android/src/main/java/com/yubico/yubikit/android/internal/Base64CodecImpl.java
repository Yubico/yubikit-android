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

package com.yubico.yubikit.android.internal;

import android.util.Base64;

public class Base64CodecImpl implements com.yubico.yubikit.core.internal.codec.Base64Codec {

  @Override
  public String toUrlSafeString(byte[] data) {
    return Base64.encodeToString(data, Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);
  }

  @Override
  public String toString(byte[] data) {
    return Base64.encodeToString(data, Base64.NO_WRAP | Base64.NO_PADDING);
  }

  @Override
  public byte[] fromUrlSafeString(String data) {
    return Base64.decode(data, Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);
  }

  @Override
  public byte[] fromString(String data) {
    return Base64.decode(data, Base64.NO_WRAP | Base64.NO_PADDING);
  }
}

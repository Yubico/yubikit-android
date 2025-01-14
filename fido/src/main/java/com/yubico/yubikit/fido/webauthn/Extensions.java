/*
 * Copyright (C) 2020-2024 Yubico.
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

package com.yubico.yubikit.fido.webauthn;

import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

public class Extensions {

  @Nullable
  public static Extensions fromMap(@Nullable Map<String, ?> input) {
    return input != null ? new Extensions(input) : null;
  }

  @Nullable private final Map<String, ?> extensions;

  private Extensions(@Nullable Map<String, ?> extensions) {
    this.extensions = extensions;
  }

  @Nullable
  public Object get(String extension) {
    return extensions != null ? extensions.get(extension) : null;
  }

  public boolean has(String extension) {
    return extensions != null && extensions.containsKey(extension);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    Extensions that = (Extensions) o;
    return Objects.equals(extensions, that.extensions);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(extensions);
  }
}

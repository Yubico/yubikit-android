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

package com.yubico.yubikit.management;

import com.yubico.yubikit.core.Version;
import java.util.Objects;

public class VersionQualifier {
  private final Version version;
  private final Type type;
  private final int iteration;

  public enum Type {
    ALPHA((byte) 0),
    BETA((byte) 1),
    FINAL((byte) 2);

    private final byte value;

    Type(byte value) {
      this.value = value;
    }

    public static Type fromValue(int value) {
      for (Type type : Type.values()) {
        if (type.value == value) {
          return type;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }

    @Override
    public String toString() {
      return name().toLowerCase();
    }
  }

  public VersionQualifier(Version version, Type type, int iteration) {
    this.version = version;
    this.type = type;
    this.iteration = iteration;
  }

  public Version getVersion() {
    return version;
  }

  public Type getType() {
    return type;
  }

  public int getIteration() {
    return iteration;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    VersionQualifier that = (VersionQualifier) o;
    return iteration == that.iteration
        && Objects.equals(version, that.version)
        && type == that.type;
  }

  @Override
  public int hashCode() {
    return Objects.hash(version, type, iteration);
  }

  @Override
  public String toString() {
    return version + "." + type + "." + Integer.toUnsignedLong(iteration);
  }
}

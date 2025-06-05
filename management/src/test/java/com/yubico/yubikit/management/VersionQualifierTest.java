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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;

import com.yubico.yubikit.core.Version;
import org.junit.Test;

public class VersionQualifierTest {
  @Test
  public void testVersion() {
    Version version = new Version(5, 7, 2);
    assertEquals(
        version, new VersionQualifier(version, VersionQualifier.Type.ALPHA, 1).getVersion());
  }

  @Test
  public void testType() {
    assertEquals(
        VersionQualifier.Type.ALPHA,
        new VersionQualifier(new Version(5, 7, 2), VersionQualifier.Type.ALPHA, 1).getType());
    assertEquals(
        VersionQualifier.Type.BETA,
        new VersionQualifier(new Version(5, 7, 2), VersionQualifier.Type.BETA, 1).getType());
    assertEquals(
        VersionQualifier.Type.FINAL,
        new VersionQualifier(new Version(5, 7, 2), VersionQualifier.Type.FINAL, 1).getType());
  }

  @Test
  public void testIteration() {
    Version version = new Version(5, 7, 2);
    VersionQualifier.Type type = VersionQualifier.Type.ALPHA;
    assertEquals(0, new VersionQualifier(version, type, 0).getIteration());
    assertEquals(128, new VersionQualifier(version, type, 128).getIteration());
    assertEquals(255, new VersionQualifier(version, type, 255).getIteration());
  }

  @Test
  public void testToString() {
    assertEquals(
        "5.7.2.alpha.0",
        new VersionQualifier(new Version(5, 7, 2), VersionQualifier.Type.ALPHA, 0).toString());
    assertEquals(
        "5.6.6.beta.16384",
        new VersionQualifier(new Version(5, 6, 6), VersionQualifier.Type.BETA, 16384).toString());
    assertEquals(
        "3.4.0.final.2147483648",
        new VersionQualifier(new Version(3, 4, 0), VersionQualifier.Type.FINAL, 0x80000000)
            .toString());
    assertEquals(
        "3.4.0.final.2147483647",
        new VersionQualifier(new Version(3, 4, 0), VersionQualifier.Type.FINAL, 0x7fffffff)
            .toString());
  }

  @Test
  public void testEqualsAndHashCode() {
    Version version1 = new Version(1, 0, 0);
    Version version2 = new Version(1, 0, 0);
    VersionQualifier qualifier1 = new VersionQualifier(version1, VersionQualifier.Type.ALPHA, 1);
    VersionQualifier qualifier2 = new VersionQualifier(version2, VersionQualifier.Type.ALPHA, 1);
    VersionQualifier qualifier3 = new VersionQualifier(version1, VersionQualifier.Type.BETA, 2);

    assertEquals(qualifier1, qualifier2);
    assertEquals(qualifier1.hashCode(), qualifier2.hashCode());
    assertNotEquals(qualifier1, qualifier3);
    assertNotEquals(qualifier1.hashCode(), qualifier3.hashCode());
  }

  @Test
  public void testTypeFromValue() {
    assertEquals(VersionQualifier.Type.ALPHA, VersionQualifier.Type.fromValue(0));
    assertEquals(VersionQualifier.Type.BETA, VersionQualifier.Type.fromValue(1));
    assertEquals(VersionQualifier.Type.FINAL, VersionQualifier.Type.fromValue(2));
    assertThrows(IllegalArgumentException.class, () -> VersionQualifier.Type.fromValue(3));
  }
}

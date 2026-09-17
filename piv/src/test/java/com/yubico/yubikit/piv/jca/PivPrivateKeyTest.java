/*
 * Copyright (C) 2026 Yubico.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import com.yubico.yubikit.piv.Slot;
import java.lang.reflect.Method;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import org.jspecify.annotations.Nullable;
import org.junit.Test;

/**
 * Covers the {@code getParams()} declaration on {@link PivPrivateKey}, which resolves the default
 * method conflict between {@code AsymmetricKey} and {@code RSAKey} on Java 24+. The lookup uses
 * reflection because this source is compiled for Java 8, where {@code PrivateKey} declares no
 * {@code getParams()}.
 */
public class PivPrivateKeyTest {

  @Test
  public void rsaKeyResolvesGetParamsToAClassMethod() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    PublicKey publicKey = generator.generateKeyPair().getPublic();

    PivPrivateKey key = PivPrivateKey.from(publicKey, Slot.SIGNATURE, null, null, null);

    Method getParams = findGenericGetParams(key);
    assertNotNull("RsaKey exposes no getParams() returning AlgorithmParameterSpec", getParams);
    assertFalse(
        "getParams() resolves to an interface default, which is ambiguous on Java 24+",
        getParams.getDeclaringClass().isInterface());
    assertNull(getParams.invoke(key));

    assertEquals(((RSAPublicKey) publicKey).getModulus(), ((RSAKey) key).getModulus());
  }

  @Test
  public void ecKeyParamsAreVisibleThroughTheGenericAccessor() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    PublicKey publicKey = generator.generateKeyPair().getPublic();
    ECParameterSpec expected = ((ECPublicKey) publicKey).getParams();

    PivPrivateKey key = PivPrivateKey.from(publicKey, Slot.AUTHENTICATION, null, null, null);

    assertSame(expected, ((ECKey) key).getParams());

    // The covariant override only reaches a PrivateKey reference through a bridge method, which
    // javac emits solely because PivPrivateKey declares getParams() as a class method.
    Method getParams = findGenericGetParams(key);
    assertNotNull("EcKey exposes no getParams() returning AlgorithmParameterSpec", getParams);
    assertSame(expected, getParams.invoke(key));
  }

  /**
   * Finds the zero-argument {@code getParams()} declaring {@code AlgorithmParameterSpec} as its
   * return type, which is the one a {@code PrivateKey} reference binds to on Java 24 and later.
   */
  @Nullable
  private static Method findGenericGetParams(PivPrivateKey key) {
    for (Method method : key.getClass().getMethods()) {
      if (method.getName().equals("getParams")
          && method.getParameterTypes().length == 0
          && method.getReturnType() == AlgorithmParameterSpec.class) {
        return method;
      }
    }
    return null;
  }
}

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

package com.yubico.yubikit.fido.ctap;

import static com.yubico.yubikit.fido.TestUtils.decodeHex;
import static com.yubico.yubikit.fido.TestUtils.encodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

public class ConfigTest {
  private static final String AAGUID = "00000000000000000000000000000000";

  // {1: ["FIDO_2_1"], 3: aaguid, 4: {"authnrCfg": true}, ...}
  private static final String INFO_BODY =
      "01"
          + "81"
          + "684649444f5f325f31"
          + "03"
          + "50"
          + AAGUID
          + "04"
          + "a1"
          + "69617574686e724366"
          + "67"
          + "f5";

  private static String info(String extraEntries, int extraCount) {
    return String.format("%02x", 0xa0 | (3 + extraCount)) + INFO_BODY + extraEntries;
  }

  private static Ctap2Session session(String infoCbor) throws Exception {
    Ctap2Session.Backend<?, ?> backend = mock(Ctap2Session.Backend.class);
    when(backend.sendCbor(any(), isNull()))
        .thenAnswer(
            invocation -> {
              byte[] request = invocation.getArgument(0);
              return request[0] == 0x04 ? decodeHex("00" + infoCbor) : new byte[] {0};
            });
    return new Ctap2Session(new Version(5, 7, 0), backend);
  }

  private static Ctap2Session.Backend<?, ?> backendOf(Ctap2Session session) throws Exception {
    java.lang.reflect.Field field = Ctap2Session.class.getDeclaredField("backend");
    field.setAccessible(true);
    return (Ctap2Session.Backend<?, ?>) field.get(session);
  }

  @Test
  public void vendorPrototypeSendsSubCommandAs255() throws Exception {
    Ctap2Session session = session(info("", 0));
    new Config(session, null, null).vendorPrototype(7);

    // authenticatorConfig (0x0d) {1: 0xff, 2: {1: 7}}
    assertEquals("0da20118ff02a10107", sentConfig(session));
  }

  @Test
  public void vendorPrototypeSendsIdAs64BitUnsigned() throws Exception {
    Ctap2Session session = session(info("", 0));
    new Config(session, null, null).vendorPrototype(0x4e5a15aa89d2b8b6L);

    // authenticatorConfig (0x0d) {1: 0xff, 2: {1: id}}
    assertEquals("0da201" + "18ff" + "02a1011b4e5a15aa89d2b8b6", sentConfig(session));
  }

  @Test
  public void vendorPrototypeSendsIdAboveSignedRangeAsUnsigned() throws Exception {
    Ctap2Session session = session(info("", 0));
    new Config(session, null, null).vendorPrototype(-1L);

    assertEquals("0da20118ff02a1011bffffffffffffffff", sentConfig(session));
  }

  @Test
  public void vendorPrototypeSendsSmallIdCanonically() throws Exception {
    Ctap2Session session = session(info("", 0));
    new Config(session, null, null).vendorPrototype(7L);

    assertEquals("0da20118ff02a10107", sentConfig(session));
  }

  @Test
  public void vendorPrototypeSendsExtraParams() throws Exception {
    Ctap2Session session = session(info("", 0));
    new Config(session, null, null)
        .vendorPrototype(7L, Collections.singletonMap(2, new byte[] {1, 2}));

    assertEquals("0da20118ff02a2010702420102", sentConfig(session));
  }

  @Test(expected = IllegalArgumentException.class)
  public void vendorPrototypeRejectsExtraParamsWithCommandIdKey() throws Exception {
    Ctap2Session session = session(info("", 0));
    new Config(session, null, null).vendorPrototype(7L, Collections.singletonMap(1, 8));
  }

  /** Hex of the last request sent to the authenticator. */
  private static String sentConfig(Ctap2Session session) throws Exception {
    ArgumentCaptor<byte[]> captor = ArgumentCaptor.forClass(byte[].class);
    verify(backendOf(session), org.mockito.Mockito.atLeast(2)).sendCbor(captor.capture(), any());
    byte[] last = captor.getValue();
    assertNotNull(last);
    assertArrayEquals(new byte[] {0x0d}, Arrays.copyOf(last, 1));
    return encodeHex(last);
  }
}

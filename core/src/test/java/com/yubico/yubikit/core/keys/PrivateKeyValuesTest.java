/*
 * Copyright (C) 2023 Yubico.
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

package com.yubico.yubikit.core.keys;

import com.yubico.yubikit.core.internal.codec.Base64;
import org.junit.Test;

@SuppressWarnings("SpellCheckingInspection")
public class PrivateKeyValuesTest {
  @Test
  public void testParsePkcs8RsaKeyValues() {
    PrivateKeyValues.Rsa.parsePkcs8RsaKeyValues(
        Base64.fromUrlSafeString(
            "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALWeZ0E5O2l_iHfck9mokf1iWH2eZDWQoJoQK"
                + "UOAeVoKUecNp250J5tL3EHONqWoF6VLO-B-6jTET4Iz97BeUj7gOJHmEw-nqFfguTVmNeeiZ711TNYN"
                + "pF7kwW7yWghWG-Q7iQEoMXfY3x4BL33H2gKRWtMHK66GJViL1l9s3qDXAgMBAAECgYBO753pFzrfS3L"
                + "Axbns6_snqcrULjdXoJhs3YFRuVEE9V9LkP-oXguoz3vXjgzqSvib-ur3U7HvZTM5X-TTXutXdQ5CyO"
                + "RLLtXEZcyCKQI9ihH5fSNJRWRbJ3xe-xi5NANRkRDkro7tm4a5ZD4PYvO4r29yVB5PXlMkOTLoxNSww"
                + "QJBAN5lW93Agi9Ge5B2-B2EnKSlUvj0-jJBkHYAFTiHyTZVEj6baeHBvJklhVczpWvTXb6Nr8cjAKVs"
                + "hFbdQoBwHmkCQQDRD7djZGIWH1Lz0rkL01nDj4z4QYMgUs3AQhnrXPBjEgNzphtJ2u7QrCSOBQQHlmA"
                + "PBDJ_MTxFJMzDIJGDA10_AkATJjEZz_ilr3D2SHgmuoNuXdneG-HrL-ALeQhavL5jkkGm6GTejnr5yN"
                + "RJZOYKecGppbOL9wSYOdbPT-_o9T55AkATXCY6cRBYRhxTcf8q5i6Y2pFOaBqxgpmFJVnrHtcwBXoGW"
                + "qqKQ1j8QAS-lh5SaY2JtnTKrI-NQ6Qmqbxv6n7XAkBkhLO7pplInVh2WjqXOV4ZAoOAAJlfpG5-z6mW"
                + "zCZ9-286OJQLr6OVVQMcYExUO9yVocZQX-4XqEIF0qAB7m31"));
  }
}

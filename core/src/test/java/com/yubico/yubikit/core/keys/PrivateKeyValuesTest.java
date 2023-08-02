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

import com.yubico.yubikit.testing.Codec;

import org.junit.Test;

import java.io.UnsupportedEncodingException;

public class PrivateKeyValuesTest {
    @Test
    public void testParsePkcs8RsaKeyValues() throws UnsupportedEncodingException {
        PrivateKeyValues.Rsa.parsePkcs8RsaKeyValues(Codec.fromBase64("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALWeZ0E5O2l/iHfc" +
                "k9mokf1iWH2eZDWQoJoQKUOAeVoKUecNp250J5tL3EHONqWoF6VLO+B+6jTET4Iz" +
                "97BeUj7gOJHmEw+nqFfguTVmNeeiZ711TNYNpF7kwW7yWghWG+Q7iQEoMXfY3x4B" +
                "L33H2gKRWtMHK66GJViL1l9s3qDXAgMBAAECgYBO753pFzrfS3LAxbns6/snqcrU" +
                "LjdXoJhs3YFRuVEE9V9LkP+oXguoz3vXjgzqSvib+ur3U7HvZTM5X+TTXutXdQ5C" +
                "yORLLtXEZcyCKQI9ihH5fSNJRWRbJ3xe+xi5NANRkRDkro7tm4a5ZD4PYvO4r29y" +
                "VB5PXlMkOTLoxNSwwQJBAN5lW93Agi9Ge5B2+B2EnKSlUvj0+jJBkHYAFTiHyTZV" +
                "Ej6baeHBvJklhVczpWvTXb6Nr8cjAKVshFbdQoBwHmkCQQDRD7djZGIWH1Lz0rkL" +
                "01nDj4z4QYMgUs3AQhnrXPBjEgNzphtJ2u7QrCSOBQQHlmAPBDJ/MTxFJMzDIJGD" +
                "A10/AkATJjEZz/ilr3D2SHgmuoNuXdneG+HrL+ALeQhavL5jkkGm6GTejnr5yNRJ" +
                "ZOYKecGppbOL9wSYOdbPT+/o9T55AkATXCY6cRBYRhxTcf8q5i6Y2pFOaBqxgpmF" +
                "JVnrHtcwBXoGWqqKQ1j8QAS+lh5SaY2JtnTKrI+NQ6Qmqbxv6n7XAkBkhLO7pplI" +
                "nVh2WjqXOV4ZAoOAAJlfpG5+z6mWzCZ9+286OJQLr6OVVQMcYExUO9yVocZQX+4X" +
                "qEIF0qAB7m31"));
    }
}

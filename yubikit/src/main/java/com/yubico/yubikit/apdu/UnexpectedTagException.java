/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.apdu;

import java.util.Locale;

public class UnexpectedTagException extends ApduException {
    public UnexpectedTagException(int expectedValue, int receivedValue) {
        super(String.format(Locale.ROOT, "Unexpected response in response. Expected: 0x%02x got: 0x%02x", expectedValue, receivedValue));
    }
}

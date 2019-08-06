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

package com.yubico.yubikit.transport;

import androidx.annotation.NonNull;

import com.yubico.yubikit.exceptions.YubikeyCommunicationException;

import java.io.IOException;

/**
 * Session for communication with YubiKey
 * Implementation of this session allows to connect to YubiKey with some transportation protocol (ex, USB_TRANSPORT or NFC_TRANSPORT)
 */
public interface YubiKeySession {

    /**
     * Creates and starts session for communication with yubikey using protocol ISO-7816 if it's supported by connected device
     * @return session for communication with yubikey using protocol ISO-7816 (Smart card)
     * @throws YubikeyCommunicationException if CCID interface or endpoints are not found
     */
    @NonNull
    Iso7816Connection openIso7816Connection() throws IOException;
}

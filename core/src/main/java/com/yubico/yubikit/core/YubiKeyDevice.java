/*
 * Copyright (C) 2020 Yubico.
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
package com.yubico.yubikit.core;

import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;

import java.io.IOException;

/**
 * A reference to a physical YubiKey.
 */
public interface YubiKeyDevice {
    /**
     * Returns the transport used for communication
     */
    Transport getTransport();

    /**
     * Returns whether or not a specific connection type is supported for this YubiKey, over this transport.
     */
    boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType);

    /**
     * Requests a new connection of the given connection type.
     */
    <T extends YubiKeyConnection> void requestConnection(Class<T> connectionType, Callback<Result<T, IOException>> callback);
}

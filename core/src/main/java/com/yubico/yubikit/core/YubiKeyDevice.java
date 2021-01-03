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
    <T extends YubiKeyConnection> void requestConnection(Class<T> connectionType, ConnectionCallback<? super T> callback);

    /**
     * Callback for handling a YubiKey connection.
     * <p>
     * Once the callback returns, the Connection is automatically closed.
     *
     * @param <T> The type of connection handled by the callback.
     */
    abstract class ConnectionCallback<T extends YubiKeyConnection> {
        /**
         * Called once the connection has been established.
         *
         * @param connection the connection, which can be used within this method.
         */
        public abstract void onConnection(T connection);

        /**
         * In case there was an error opening the connection, or invoking the callback.
         *
         * @param error the Exception which was thrown.
         */
        public void onError(Exception error) {
            Logger.e("Error in connection callback:", error);
        }
    }
}

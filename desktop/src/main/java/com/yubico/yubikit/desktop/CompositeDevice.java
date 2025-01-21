/*
 * Copyright (C) 2022-2025 Yubico.
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
package com.yubico.yubikit.desktop;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import java.io.Closeable;
import java.io.IOException;

public class CompositeDevice implements YubiKeyDevice, Closeable {
  private final UsbPidGroup pidGroup;
  private final String key;

  CompositeDevice(UsbPidGroup pidGroup, String key) {
    this.pidGroup = pidGroup;
    this.key = key;
  }

  @Override
  public Transport getTransport() {
    return Transport.USB;
  }

  @Override
  public boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType) {
    return pidGroup.supportsConnection(connectionType);
  }

  @Override
  public <T extends YubiKeyConnection> void requestConnection(
      Class<T> connectionType, Callback<Result<T, IOException>> callback) {
    pidGroup.requestConnection(key, connectionType, callback);
  }

  @Override
  public <T extends YubiKeyConnection> T openConnection(Class<T> connectionType)
      throws IOException {
    return pidGroup.openConnection(key, connectionType);
  }

  public UsbPidGroup getPidGroup() {
    return pidGroup;
  }

  @Override
  public void close() throws IOException {
    pidGroup.close();
  }
}

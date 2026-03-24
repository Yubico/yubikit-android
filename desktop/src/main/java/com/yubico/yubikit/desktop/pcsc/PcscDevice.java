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
package com.yubico.yubikit.desktop.pcsc;

import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

abstract class PcscDevice implements YubiKeyDevice, Closeable {
  private final ExecutorService executorService = Executors.newSingleThreadExecutor();
  private final CardTerminal terminal;

  public PcscDevice(CardTerminal terminal) {
    this.terminal = terminal;
  }

  public String getName() {
    return terminal.getName();
  }

  public SmartCardConnection openIso7816Connection() throws IOException {
    try {
      return new PcscSmartCardConnection(terminal.connect("T=1"));
    } catch (CardException e) {
      throw new IOException(e);
    }
  }

  @Override
  public boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType) {
    return connectionType.isAssignableFrom(PcscSmartCardConnection.class);
  }

  public <T extends YubiKeyConnection> T openConnection(Class<T> connectionType)
      throws IOException {

    if (!supportsConnection(connectionType)) {
      throw new IllegalStateException("Unsupported connection type");
    }

    return connectionType.cast(openIso7816Connection());
  }

  @Override
  public <T extends YubiKeyConnection> void requestConnection(
      Class<T> connectionType, Callback<Result<T, IOException>> callback) {
    if (!supportsConnection(connectionType)) {
      throw new IllegalStateException("Unsupported connection type");
    }
    executorService.submit(
        () -> {
          try (T connection = openConnection(connectionType)) {
            callback.invoke(Result.success(connection));
          } catch (IOException e) {
            callback.invoke(Result.failure(e));
          }
        });
  }

  @Override
  public void close() throws IOException {
    executorService.shutdown();
  }
}

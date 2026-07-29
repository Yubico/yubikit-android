/*
 * Copyright (C) 2022-2026 Yubico.
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
import org.jspecify.annotations.Nullable;

abstract class PcscDevice implements YubiKeyDevice, Closeable {
  private final CardTerminal terminal;
  private volatile @Nullable ExecutorService executorService;

  public PcscDevice(CardTerminal terminal) {
    this.terminal = terminal;
  }

  private ExecutorService getExecutorService() {
    ExecutorService executor = executorService;
    if (executor == null) {
      synchronized (this) {
        executor = executorService;
        if (executor == null) {
          executor = Executors.newSingleThreadExecutor();
          executorService = executor;
        }
      }
    }
    return executor;
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
    getExecutorService()
        .submit(
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
    ExecutorService executor = executorService;
    if (executor != null) {
      executor.shutdown();
    }
  }
}

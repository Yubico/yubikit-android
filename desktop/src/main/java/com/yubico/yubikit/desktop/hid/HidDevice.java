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
package com.yubico.yubikit.desktop.hid;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.desktop.UsbYubiKeyDevice;
import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HidDevice implements UsbYubiKeyDevice, Closeable {
  private final ExecutorService executorService = Executors.newSingleThreadExecutor();
  private final org.hid4java.HidDevice hidDevice;
  private final int usagePage;

  HidDevice(org.hid4java.HidDevice hidDevice) {
    this.hidDevice = hidDevice;
    usagePage = hidDevice.getUsagePage() & 0xffff;
  }

  public HidOtpConnection openOtpConnection() throws IOException {
    return new HidOtpConnection(hidDevice, (byte) 0);
  }

  public HidFidoConnection openFidoConnection() throws IOException {
    if (usagePage == 0xf1d0) {
      return new HidFidoConnection(hidDevice);
    }
    throw new IOException("fido connection not supported");
  }

  @Override
  public Transport getTransport() {
    return Transport.USB;
  }

  @Override
  public boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType) {
    if (connectionType.isAssignableFrom(HidOtpConnection.class)) {
      return usagePage == 1;
    } else if (connectionType.isAssignableFrom(HidFidoConnection.class)) {
      return usagePage == 0xf1d0;
    }
    return false;
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
  public <T extends YubiKeyConnection> T openConnection(Class<T> connectionType)
      throws IOException {
    if (connectionType.isAssignableFrom(HidOtpConnection.class)) {
      return connectionType.cast(openOtpConnection());
    } else if (connectionType.isAssignableFrom(HidFidoConnection.class)) {
      return connectionType.cast(openFidoConnection());
    }
    throw new IllegalStateException("Unsupported connection type");
  }

  @Override
  public String getFingerprint() {
    return hidDevice.getPath();
  }

  @Override
  public UsbPid getPid() {
    return UsbPid.fromValue(hidDevice.getProductId());
  }

  @Override
  public void close() throws IOException {
    executorService.shutdown();
  }
}

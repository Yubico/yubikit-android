/*
 * Copyright (C) 2019-2025 Yubico.
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

package com.yubico.yubikit.android.transport.usb;

import static com.yubico.yubikit.android.transport.usb.UsbDeviceManager.YUBICO_VENDOR_ID;

import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import com.yubico.yubikit.android.transport.usb.connection.ConnectionManager;
import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

public class UsbYubiKeyDevice implements YubiKeyDevice, Closeable {

  private final ExecutorService executorService = Executors.newSingleThreadExecutor();
  private final ConnectionManager connectionManager;
  private final UsbManager usbManager;
  private final UsbDevice usbDevice;
  private final UsbPid usbPid;

  @Nullable private CachedOtpConnection otpConnection = null;

  @Nullable private Runnable onClosed = null;

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(UsbYubiKeyDevice.class);

  /**
   * Creates the instance of usb session to interact with the yubikey device.
   *
   * @param usbManager UsbManager for accessing USB devices
   * @param usbDevice device connected over usb that has permissions to interact with
   * @throws IllegalArgumentException when the usbDevice is not a recognized YubiKey
   */
  public UsbYubiKeyDevice(UsbManager usbManager, UsbDevice usbDevice)
      throws IllegalArgumentException {

    if (usbDevice.getVendorId() != YUBICO_VENDOR_ID) {
      throw new IllegalArgumentException("Invalid vendor id");
    }

    this.usbPid = UsbPid.fromValue(usbDevice.getProductId());

    this.connectionManager = new ConnectionManager(usbManager, usbDevice);
    this.usbDevice = usbDevice;
    this.usbManager = usbManager;
  }

  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  public boolean hasPermission() {
    return usbManager.hasPermission(usbDevice);
  }

  /**
   * Returns yubikey device attached to the android device with the android device acting as the USB
   * host. It describes the capabilities of the USB device and allows to get properties/name/product
   * id/manufacturer of device
   *
   * @return yubikey device connected over USB
   */
  public UsbDevice getUsbDevice() {
    return usbDevice;
  }

  /**
   * @return {@link UsbPid} for the device's product id
   */
  public UsbPid getPid() {
    return usbPid;
  }

  @Override
  public Transport getTransport() {
    return Transport.USB;
  }

  @Override
  public boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType) {
    return connectionManager.supportsConnection(connectionType);
  }

  @Override
  public <T extends YubiKeyConnection> void requestConnection(
      Class<T> connectionType, Callback<Result<T, IOException>> callback) {
    verifyAccess(connectionType);

    // Keep UsbOtpConnection open until another connection is needed, to prevent re-enumeration of
    // the USB device.
    if (OtpConnection.class.isAssignableFrom(connectionType)) {
      @SuppressWarnings("unchecked")
      Callback<Result<OtpConnection, IOException>> otpCallback =
          value -> callback.invoke((Result<T, IOException>) value);
      if (otpConnection == null) {
        otpConnection = new CachedOtpConnection(otpCallback);
      } else {
        otpConnection.queue.offer(otpCallback);
      }
    } else {
      if (otpConnection != null) {
        otpConnection.close();
        otpConnection = null;
      }
      executorService.submit(
          () -> {
            try (T connection = connectionManager.openConnection(connectionType)) {
              callback.invoke(Result.success(connection));
            } catch (IOException e) {
              callback.invoke(Result.failure(e));
            } catch (Exception exception) {
              callback.invoke(
                  Result.failure(
                      new IOException(
                          "openConnection("
                              + connectionType.getSimpleName()
                              + ") exception: "
                              + exception.getMessage(),
                          exception)));
            }
          });
    }
  }

  @Override
  public <T extends YubiKeyConnection> T openConnection(Class<T> connectionType)
      throws IOException {
    verifyAccess(connectionType);

    return connectionManager.openConnection(connectionType);
  }

  public void setOnClosed(Runnable onClosed) {
    if (executorService.isTerminated()) {
      onClosed.run();
    } else {
      this.onClosed = onClosed;
    }
  }

  @Override
  public void close() {
    Logger.debug(logger, "Closing YubiKey device");
    if (otpConnection != null) {
      otpConnection.close();
      otpConnection = null;
    }
    if (onClosed != null) {
      executorService.submit(onClosed);
    }
    executorService.shutdown();
  }

  private static final Callback<Result<OtpConnection, IOException>> CLOSE_OTP = value -> {};

  private class CachedOtpConnection implements Closeable {
    private final LinkedBlockingQueue<Callback<Result<OtpConnection, IOException>>> queue =
        new LinkedBlockingQueue<>();

    private CachedOtpConnection(Callback<Result<OtpConnection, IOException>> callback) {
      Logger.debug(logger, "Creating new CachedOtpConnection");
      queue.offer(callback);
      executorService.submit(
          () -> {
            try (OtpConnection connection = connectionManager.openConnection(OtpConnection.class)) {
              while (true) {
                try {
                  Callback<Result<OtpConnection, IOException>> action = queue.take();
                  if (action == CLOSE_OTP) {
                    Logger.debug(logger, "Closing CachedOtpConnection");
                    break;
                  }
                  try {
                    action.invoke(Result.success(connection));
                  } catch (Exception e) {
                    Logger.error(logger, "OtpConnection callback threw an exception", e);
                  }
                } catch (InterruptedException e) {
                  Logger.error(logger, "InterruptedException when processing OtpConnection: ", e);
                }
              }
            } catch (IOException e) {
              callback.invoke(Result.failure(e));
            } catch (Exception exception) {
              callback.invoke(
                  Result.failure(
                      new IOException(
                          "openConnection(OtpConnection) exception: " + exception.getMessage(),
                          exception)));
            }
          });
    }

    @Override
    public void close() {
      queue.offer(CLOSE_OTP);
    }
  }

  /**
   * Throw if the device cannot create connections of the specified type.
   *
   * @param connectionType type of connection to verify
   * @throws IllegalStateException if the USB permission has not been granted
   * @throws IllegalStateException if the connectionType is not supported
   */
  private <T extends YubiKeyConnection> void verifyAccess(Class<T> connectionType) {
    if (!hasPermission()) {
      throw new IllegalStateException("Device access not permitted");
    } else if (!supportsConnection(connectionType)) {
      throw new IllegalStateException("Unsupported connection type");
    }
  }

  @Nonnull
  @Override
  public String toString() {
    return "UsbYubiKeyDevice{" + "usbDevice=" + usbDevice + ", usbPid=" + usbPid + '}';
  }
}

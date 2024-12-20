/*
 * Copyright (C) 2022-2023 Yubico.
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

import android.content.Context;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import com.yubico.yubikit.android.transport.usb.connection.ConnectionManager;
import com.yubico.yubikit.android.transport.usb.connection.FidoConnectionHandler;
import com.yubico.yubikit.android.transport.usb.connection.OtpConnectionHandler;
import com.yubico.yubikit.android.transport.usb.connection.SmartCardConnectionHandler;
import com.yubico.yubikit.android.transport.usb.connection.UsbFidoConnection;
import com.yubico.yubikit.android.transport.usb.connection.UsbOtpConnection;
import com.yubico.yubikit.android.transport.usb.connection.UsbSmartCardConnection;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.util.Callback;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

public class UsbYubiKeyManager {
  static {
    ConnectionManager.registerConnectionHandler(
        UsbSmartCardConnection.class, new SmartCardConnectionHandler());
    ConnectionManager.registerConnectionHandler(UsbOtpConnection.class, new OtpConnectionHandler());
    ConnectionManager.registerConnectionHandler(
        UsbFidoConnection.class, new FidoConnectionHandler());
  }

  private final Context context;
  private final UsbManager usbManager;
  @Nullable private MyDeviceListener internalListener = null;

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(UsbYubiKeyManager.class);

  public UsbYubiKeyManager(Context context) {
    this.context = context;
    usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
  }

  /**
   * Registers receiver on usb connection event
   *
   * @param usbConfiguration contains information if device manager also registers receiver on
   *     permissions grant from user
   * @param listener the UsbSessionListener to react to changes
   */
  public synchronized void enable(
      UsbConfiguration usbConfiguration, Callback<? super UsbYubiKeyDevice> listener) {
    disable();
    internalListener = new MyDeviceListener(usbConfiguration, listener);
    UsbDeviceManager.registerUsbListener(context, internalListener);
  }

  public synchronized void disable() {
    if (internalListener != null) {
      UsbDeviceManager.unregisterUsbListener(context, internalListener);
      internalListener = null;
    }
  }

  private class MyDeviceListener implements UsbDeviceManager.UsbDeviceListener {
    private final Callback<? super UsbYubiKeyDevice> listener;
    private final UsbConfiguration usbConfiguration;
    private final Map<UsbDevice, UsbYubiKeyDevice> devices = new HashMap<>();

    private MyDeviceListener(
        UsbConfiguration usbConfiguration, Callback<? super UsbYubiKeyDevice> listener) {
      this.usbConfiguration = usbConfiguration;
      this.listener = listener;
    }

    @Override
    public void deviceAttached(UsbDevice usbDevice) {

      try {
        UsbYubiKeyDevice yubikey = new UsbYubiKeyDevice(usbManager, usbDevice);
        devices.put(usbDevice, yubikey);

        if (usbConfiguration.isHandlePermissions() && !yubikey.hasPermission()) {
          Logger.debug(logger, "request permission");
          UsbDeviceManager.requestPermission(
              context,
              usbDevice,
              (usbDevice1, hasPermission) -> {
                Logger.debug(logger, "permission result {}", hasPermission);
                if (hasPermission) {
                  synchronized (UsbYubiKeyManager.this) {
                    if (internalListener == this) {
                      listener.invoke(yubikey);
                    }
                  }
                }
              });
        } else {
          listener.invoke(yubikey);
        }
      } catch (IllegalArgumentException ignored) {
        Logger.debug(
            logger,
            "Attached usbDevice(vid={},pid={}) is not recognized as a valid YubiKey",
            usbDevice.getVendorId(),
            usbDevice.getProductId());
      }
    }

    @Override
    public void deviceRemoved(UsbDevice usbDevice) {
      UsbYubiKeyDevice yubikey = devices.remove(usbDevice);
      if (yubikey != null) {
        yubikey.close();
      }
    }
  }
}

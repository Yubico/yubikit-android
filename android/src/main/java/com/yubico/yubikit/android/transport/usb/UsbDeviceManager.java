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

import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.os.Build;
import com.yubico.yubikit.core.internal.Logger;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.WeakHashMap;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

final class UsbDeviceManager {

  private static final String ACTION_USB_PERMISSION = "com.yubico.yubikey.USB_PERMISSION";
  public static final int YUBICO_VENDOR_ID = 0x1050;

  @Nullable private static UsbDeviceManager instance;

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(UsbDeviceManager.class);

  private static synchronized UsbDeviceManager getInstance() {
    if (instance == null) {
      instance = new UsbDeviceManager();
    }
    return instance;
  }

  static void registerUsbListener(Context context, UsbDeviceListener listener) {
    getInstance().addUsbListener(context, listener);
  }

  static void unregisterUsbListener(Context context, UsbDeviceListener listener) {
    getInstance().removeUsbListener(context, listener);
  }

  static void requestPermission(
      Context context, UsbDevice usbDevice, PermissionResultListener listener) {
    getInstance().requestDevicePermission(context, usbDevice, listener);
  }

  private final DeviceBroadcastReceiver broadcastReceiver = new DeviceBroadcastReceiver();
  private final PermissionBroadcastReceiver permissionReceiver = new PermissionBroadcastReceiver();
  private final Set<UsbDeviceListener> deviceListeners = new HashSet<>();
  private final WeakHashMap<UsbDevice, Set<PermissionResultListener>> contexts =
      new WeakHashMap<>();
  private final Set<UsbDevice> awaitingPermissions = new HashSet<>();

  private synchronized void addUsbListener(Context context, UsbDeviceListener listener) {
    if (deviceListeners.isEmpty()) {
      UsbManager usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
      Collection<UsbDevice> usbDevices = usbManager.getDeviceList().values();
      IntentFilter intentFilter = new IntentFilter(UsbManager.ACTION_USB_DEVICE_ATTACHED);
      intentFilter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
      context.registerReceiver(broadcastReceiver, intentFilter);
      for (UsbDevice usbDevice : usbDevices) {
        if (usbDevice.getVendorId() == YUBICO_VENDOR_ID) {
          onDeviceAttach(usbDevice);
        }
      }
    }
    deviceListeners.add(listener);
    for (UsbDevice usbDevice : contexts.keySet()) {
      listener.deviceAttached(usbDevice);
    }
  }

  private synchronized void removeUsbListener(Context context, UsbDeviceListener listener) {
    deviceListeners.remove(listener);
    for (UsbDevice usbDevice : contexts.keySet()) {
      listener.deviceRemoved(usbDevice);
    }
    if (deviceListeners.isEmpty()) {
      context.unregisterReceiver(broadcastReceiver);
      contexts.clear();
    }
  }

  private synchronized void requestDevicePermission(
      Context context, UsbDevice usbDevice, PermissionResultListener listener) {
    Set<PermissionResultListener> permissionListeners =
        Objects.requireNonNull(contexts.get(usbDevice));
    synchronized (permissionListeners) {
      permissionListeners.add(listener);
    }
    synchronized (awaitingPermissions) {
      if (!awaitingPermissions.contains(usbDevice)) {
        if (awaitingPermissions.isEmpty()) {
          registerPermissionsReceiver(context, permissionReceiver);
        }
        Logger.debug(logger, "Requesting permission for UsbDevice: {}", usbDevice.getDeviceName());
        int flags = 0;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
          flags |= PendingIntent.FLAG_MUTABLE;
        }

        Intent intent = new Intent(ACTION_USB_PERMISSION);
        intent.setPackage(context.getPackageName());

        PendingIntent pendingUsbPermissionIntent =
            PendingIntent.getBroadcast(context, 0, intent, flags);
        UsbManager usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        usbManager.requestPermission(usbDevice, pendingUsbPermissionIntent);
        awaitingPermissions.add(usbDevice);
      }
    }
  }

  private void onDeviceAttach(UsbDevice usbDevice) {
    Logger.debug(logger, "UsbDevice attached: {}", usbDevice.getDeviceName());
    contexts.put(usbDevice, new HashSet<>());
    for (UsbDeviceListener listener : deviceListeners) {
      listener.deviceAttached(usbDevice);
    }
  }

  private void onPermission(Context context, UsbDevice usbDevice, boolean permission) {
    Logger.debug(
        logger, "Permission result for {}, permitted: {}", usbDevice.getDeviceName(), permission);
    Set<PermissionResultListener> permissionListeners = contexts.get(usbDevice);
    if (permissionListeners != null) {
      synchronized (permissionListeners) {
        for (PermissionResultListener listener : permissionListeners) {
          listener.onPermissionResult(usbDevice, permission);
        }
        permissionListeners.clear();
      }
    }
    synchronized (awaitingPermissions) {
      if (awaitingPermissions.remove(usbDevice) && awaitingPermissions.isEmpty()) {
        context.unregisterReceiver(permissionReceiver);
      }
    }
  }

  private void onDeviceDetach(Context context, UsbDevice usbDevice) {
    Logger.debug(logger, "UsbDevice detached: {}", usbDevice.getDeviceName());
    if (contexts.remove(usbDevice) != null) {
      for (UsbDeviceListener listener : deviceListeners) {
        listener.deviceRemoved(usbDevice);
      }
    }
    synchronized (awaitingPermissions) {
      if (awaitingPermissions.remove(usbDevice) && awaitingPermissions.isEmpty()) {
        context.unregisterReceiver(permissionReceiver);
      }
    }
  }

  interface UsbDeviceListener {
    void deviceAttached(UsbDevice usbDevice);

    void deviceRemoved(UsbDevice usbDevice);
  }

  private class DeviceBroadcastReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
      String action = intent.getAction();
      UsbDevice usbDevice = getUsbManagerExtraDevice(intent);
      if (usbDevice == null || usbDevice.getVendorId() != YUBICO_VENDOR_ID) {
        return;
      }

      if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {
        onDeviceAttach(usbDevice);
      } else if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {
        onDeviceDetach(context, usbDevice);
      }
    }
  }

  interface PermissionResultListener {
    void onPermissionResult(UsbDevice usbDevice, boolean hasPermission);
  }

  private class PermissionBroadcastReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
      if (ACTION_USB_PERMISSION.equals(intent.getAction())) {
        UsbDevice device = getUsbManagerExtraDevice(intent);
        UsbManager usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (device != null) {
          onPermission(context, device, usbManager.hasPermission(device));
        }
      }
    }
  }

  @SuppressLint("UnspecifiedRegisterReceiverFlag")
  private static void registerPermissionsReceiver(
      Context context, PermissionBroadcastReceiver permissionReceiver) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      context.registerReceiver(
          permissionReceiver,
          new IntentFilter(ACTION_USB_PERMISSION),
          Context.RECEIVER_NOT_EXPORTED);
    } else {
      context.registerReceiver(permissionReceiver, new IntentFilter(ACTION_USB_PERMISSION));
    }
  }

  /**
   * Helper method to call {@code Intent.getParcelableExtra} based on build version
   *
   * @implNote The new API is used only on 34+ devices because of bug in API 33
   * @see <a href="https://issuetracker.google.com/issues/240585930">The new
   *     Intent.getParcelableExtra(String,Class) throws an NPE internally </a>
   * @param intent Intent to get the usb device from
   * @return UsbDevice from intent's parcelable
   */
  @Nullable
  @SuppressWarnings("deprecation")
  private static UsbDevice getUsbManagerExtraDevice(Intent intent) {
    return (Build.VERSION.SDK_INT > Build.VERSION_CODES.TIRAMISU)
        ? intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice.class)
        : intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
  }
}

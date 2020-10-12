package com.yubico.yubikit.android.transport.usb;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import com.yubico.yubikit.core.Logger;

import javax.annotation.Nullable;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

final class UsbDeviceManager {
    private final static String ACTION_USB_PERMISSION = "com.yubico.yubikey.USB_PERMISSION";
    private final static int YUBICO_VENDOR_ID = 0x1050;

    @Nullable
    private static UsbDeviceManager instance;

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

    static void requestPermission(Context context, UsbDevice usbDevice, PermissionResultListener listener) {
        getInstance().requestDevicePermission(context, usbDevice, listener);
    }

    private final DeviceBroadcastReceiver broadcastReceiver = new DeviceBroadcastReceiver();
    private final PermissionBroadcastReceiver permissionReceiver = new PermissionBroadcastReceiver();
    private final Set<UsbDeviceListener> deviceListeners = new HashSet<>();
    private final WeakHashMap<UsbDevice, DeviceContext> contexts = new WeakHashMap<>();
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
                    Logger.d("TRIGGER ATTACH ON ALREADY PRESENT DEVICE " + usbDevice);
                    onDeviceAttach(usbDevice);
                }
            }
        }
        deviceListeners.add(listener);
        for (Map.Entry<UsbDevice, DeviceContext> entry : contexts.entrySet()) {
            DeviceContext deviceContext = entry.getValue();
            deviceContext.executorService.execute(() -> listener.deviceAttached(entry.getKey(), deviceContext.connectionLock));
        }
    }

    private synchronized void removeUsbListener(Context context, UsbDeviceListener listener) {
        deviceListeners.remove(listener);
        for (Map.Entry<UsbDevice, DeviceContext> entry : contexts.entrySet()) {
            DeviceContext deviceContext = entry.getValue();
            deviceContext.executorService.execute(() -> listener.deviceRemoved(entry.getKey()));
        }
        if (deviceListeners.isEmpty()) {
            context.unregisterReceiver(broadcastReceiver);
            for (DeviceContext deviceContext : contexts.values()) {
                deviceContext.executorService.shutdown();
            }
            contexts.clear();
        }
    }

    private synchronized void requestDevicePermission(Context context, UsbDevice usbDevice, PermissionResultListener listener) {
        Logger.d("REQUEST USB PERMISSION");
        DeviceContext deviceContext = Objects.requireNonNull(contexts.get(usbDevice));
        synchronized (deviceContext.permissionListeners) {
            deviceContext.permissionListeners.add(listener);
        }
        synchronized (awaitingPermissions) {
            if (!awaitingPermissions.contains(usbDevice)) {
                if (awaitingPermissions.isEmpty()) {
                    context.registerReceiver(permissionReceiver, new IntentFilter(ACTION_USB_PERMISSION));
                }
                Logger.d("ACTUALLY REQUEST USB PERMISSION");
                PendingIntent pendingUsbPermissionIntent = PendingIntent.getBroadcast(context, 0, new Intent(ACTION_USB_PERMISSION), 0);
                UsbManager usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
                usbManager.requestPermission(usbDevice, pendingUsbPermissionIntent);
                awaitingPermissions.add(usbDevice);
            }
        }
    }

    private void onDeviceAttach(UsbDevice usbDevice) {
        Logger.d("DEVICE ATTACHED");
        DeviceContext deviceContext = new DeviceContext();
        contexts.put(usbDevice, deviceContext);
        for (UsbDeviceListener listener : deviceListeners) {
            deviceContext.executorService.execute(() -> listener.deviceAttached(usbDevice, deviceContext.connectionLock));
        }
    }

    private void onPermission(Context context, UsbDevice usbDevice, boolean permission) {
        Logger.d("ON PERMISSION");
        DeviceContext deviceContext = contexts.get(usbDevice);
        if (deviceContext != null) {
            synchronized (deviceContext.permissionListeners) {
                for (PermissionResultListener listener : deviceContext.permissionListeners) {
                    deviceContext.executorService.execute(() -> listener.onPermissionResult(usbDevice, permission));
                }
                deviceContext.permissionListeners.clear();
            }
        }
        synchronized (awaitingPermissions) {
            if (awaitingPermissions.remove(usbDevice) && awaitingPermissions.isEmpty()) {
                context.unregisterReceiver(permissionReceiver);
            }
        }
    }

    private void onDeviceDetach(Context context, UsbDevice usbDevice) {
        Logger.d("DEVICE REMOVED");
        DeviceContext deviceContext = contexts.remove(usbDevice);
        if (deviceContext != null) {
            for (UsbDeviceListener listener : deviceListeners) {
                deviceContext.executorService.execute(() -> listener.deviceRemoved(usbDevice));
            }
            deviceContext.executorService.shutdown();
        }
        synchronized (awaitingPermissions) {
            if (awaitingPermissions.remove(usbDevice) && awaitingPermissions.isEmpty()) {
                context.unregisterReceiver(permissionReceiver);
            }
        }
    }

    interface UsbDeviceListener {
        void deviceAttached(UsbDevice usbDevice, Semaphore connectionLock);

        void deviceRemoved(UsbDevice usbDevice);
    }

    private class DeviceBroadcastReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            UsbDevice usbDevice = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
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
                UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                UsbManager usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
                if (device != null) {
                    onPermission(context, device, usbManager.hasPermission(device));
                }
            }
        }
    }

    private static class DeviceContext {
        private final ExecutorService executorService = Executors.newSingleThreadExecutor();
        private final Semaphore connectionLock = new Semaphore(1);
        private final Set<PermissionResultListener> permissionListeners = new HashSet<>();
    }
}

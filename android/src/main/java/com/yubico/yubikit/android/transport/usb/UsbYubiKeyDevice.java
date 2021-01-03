/*
 * Copyright (C) 2019 Yubico.
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

import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;

import com.yubico.yubikit.android.transport.usb.connection.ConnectionManager;
import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.otp.OtpConnection;

import java.io.Closeable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

import javax.annotation.Nullable;

public class UsbYubiKeyDevice implements YubiKeyDevice, Closeable {
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();
    private final ConnectionManager connectionManager;
    private final UsbDevice usbDevice;
    @Nullable
    private CachedOtpConnection otpConnection = null;

    /**
     * Creates the instance of usb session to interact with the yubikey device.
     *
     * @param usbManager manager of usb connection
     * @param usbDevice  device connected over usb that has permissions to interact with
     */
    public UsbYubiKeyDevice(UsbManager usbManager, UsbDevice usbDevice) {
        this.connectionManager = new ConnectionManager(usbManager, usbDevice);
        this.usbDevice = usbDevice;
    }

    /**
     * Returns yubikey device attached to the android device with the android device acting as the USB host.
     * It describes the capabilities of the USB device and allows to get properties/name/product id/manufacturer of device
     *
     * @return yubikey device connected over USB
     */
    public UsbDevice getUsbDevice() {
        return usbDevice;
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
    public <T extends YubiKeyConnection> void requestConnection(Class<T> connectionType, ConnectionCallback<? super T> callback) {
        // Keep UsbOtpConnection open until another connection is needed, to prevent re-enumeration of the USB device.
        if (OtpConnection.class.isAssignableFrom(connectionType)) {
            ConnectionCallback<? super OtpConnection> otpCallback = (ConnectionCallback<? super OtpConnection>) callback;
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
            executorService.submit(() -> {
                try (T connection = connectionManager.openConnection(connectionType)) {
                    callback.onConnection(connection);
                } catch (Exception e) {
                    callback.onError(e);
                }
            });
        }
    }

    @Override
    public void close() {
        if (otpConnection != null) {
            otpConnection.close();
            otpConnection = null;
        }
        executorService.shutdown();
    }

    private static final ConnectionCallback<OtpConnection> CLOSE_OTP = new ConnectionCallback<OtpConnection>() {
        @Override
        public void onConnection(OtpConnection connection) {
            throw new IllegalStateException();
        }
    };

    private class CachedOtpConnection implements Closeable {
        private final LinkedBlockingQueue<ConnectionCallback<? super OtpConnection>> queue = new LinkedBlockingQueue<>();

        private CachedOtpConnection(ConnectionCallback<? super OtpConnection> callback) {
            Logger.d("Creating new CachedOtpConnection");
            queue.offer(callback);
            executorService.submit(() -> {
                try (OtpConnection connection = connectionManager.openConnection(OtpConnection.class)) {
                    while (true) {
                        try {
                            ConnectionCallback<? super OtpConnection> action = queue.take();
                            if (action == CLOSE_OTP) {
                                Logger.d("Closing CachedOtpConnection");
                                break;
                            }
                            try {
                                action.onConnection(connection);
                            } catch (Exception e) {
                                action.onError(e);
                            }
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                } catch (Exception e) {
                    callback.onError(e);
                }
            });
        }

        @Override
        public void close() {
            queue.offer(CLOSE_OTP);
        }
    }
}

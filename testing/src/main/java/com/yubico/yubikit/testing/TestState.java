/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.testing;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationSession;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.support.DeviceUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.Security;

import javax.annotation.Nullable;

public class TestState {
    public abstract static class Builder<T extends Builder<T>> {
        final protected YubiKeyDevice device;
        @Nullable
        final private UsbPid usbPid;
        @Nullable
        private Byte scpKid = null;
        @Nullable
        private ReconnectDeviceCallback reconnectDeviceCallback = null;

        public abstract T getThis();

        public Builder(YubiKeyDevice device, @Nullable UsbPid usbPid) {
            this.device = device;
            this.usbPid = usbPid;
        }

        public T scpKid(@Nullable Byte scpKid) {
            this.scpKid = scpKid;
            return getThis();
        }

        public T reconnectDeviceCallback(@Nullable ReconnectDeviceCallback reconnectDeviceCallback) {
            this.reconnectDeviceCallback = reconnectDeviceCallback;
            return getThis();
        }

        public abstract TestState build() throws Throwable;
    }

    protected YubiKeyDevice currentDevice;
    protected ScpParameters scpParameters;
    @Nullable
    public final UsbPid usbPid;
    @Nullable
    public final Byte scpKid;
    @Nullable
    private final ReconnectDeviceCallback reconnectDeviceCallback;
    private final boolean isUsbTransport;

    protected TestState(Builder<?> builder) {
        this.currentDevice = builder.device;
        this.usbPid = builder.usbPid;
        this.scpKid = builder.scpKid;
        this.scpParameters = new ScpParameters(builder.device, this.scpKid);
        this.reconnectDeviceCallback = builder.reconnectDeviceCallback;
        this.isUsbTransport = builder.device.getTransport() == Transport.USB;

        setupJca();
    }

    private void setupJca() {
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    public boolean isUsbTransport() {
        return isUsbTransport;
    }

    public interface StatefulDeviceCallback<S extends TestState> {
        void invoke(S state) throws Throwable;
    }

    public interface SessionCallback<T extends ApplicationSession<T>> {
        void invoke(T session) throws Throwable;
    }

    public interface StatefulSessionCallback<T extends ApplicationSession<T>, S extends TestState> {
        void invoke(T session, S state) throws Throwable;
    }

    public interface SessionCallbackT<T extends ApplicationSession<T>, R> {
        R invoke(T session) throws Throwable;
    }

    public interface ReconnectDeviceCallback {
        YubiKeyDevice invoke();
    }

    protected void reconnect() {
        if (reconnectDeviceCallback != null) {
            currentDevice = reconnectDeviceCallback.invoke();
            scpParameters = new ScpParameters(currentDevice, scpKid);
        }
    }

    public boolean isFipsCapable(DeviceInfo deviceInfo, Capability capability) {
        return deviceInfo != null &&
                (deviceInfo.getFipsCapable() & capability.bit) == capability.bit;
    }

    public boolean isFipsCapable(Capability capability) {
        return isFipsCapable(getDeviceInfo(), capability);
    }

    public boolean isFipsApproved(Capability capability) {
        return isFipsApproved(getDeviceInfo(), capability);
    }

    public boolean isFipsApproved(DeviceInfo deviceInfo, Capability capability) {
        return deviceInfo != null &&
                (deviceInfo.getFipsApproved() & capability.bit) == capability.bit;
    }

    // connection helpers
    protected SmartCardConnection openSmartCardConnection() throws IOException {
        if (currentDevice.supportsConnection(SmartCardConnection.class)) {
            return currentDevice.openConnection(SmartCardConnection.class);
        }
        return null;
    }

    protected YubiKeyConnection openConnection() throws IOException {
        if (currentDevice.supportsConnection(FidoConnection.class)) {
            return currentDevice.openConnection(FidoConnection.class);
        }
        if (currentDevice.supportsConnection(SmartCardConnection.class)) {
            return currentDevice.openConnection(SmartCardConnection.class);
        }
        throw new IllegalArgumentException("Device does not support FIDO or SmartCard connection");
    }

    // common utils
    public DeviceInfo getDeviceInfo() {
        DeviceInfo deviceInfo;
        try (YubiKeyConnection connection = openConnection()) {
            deviceInfo = DeviceUtil.readInfo(connection, usbPid);
        } catch (IOException | UnsupportedOperationException exception) {
            throw new RuntimeException("Failed to read info", exception);
        }

        return deviceInfo;
    }

    protected ManagementSession getManagementSession(YubiKeyConnection connection, ScpParameters scpParameters)
            throws IOException, CommandException {
        ScpKeyParams keyParams = scpParameters != null ? scpParameters.getKeyParams() : null;
        ManagementSession session = (connection instanceof FidoConnection)
                ? new ManagementSession((FidoConnection) connection)
                : connection instanceof SmartCardConnection
                ? new ManagementSession((SmartCardConnection) connection, keyParams)
                : null;

        if (session == null) {
            throw new IllegalArgumentException("Connection does not support ManagementSession");
        }

        return session;
    }

    protected boolean isMpe(DeviceInfo deviceInfo) {
        if (deviceInfo == null) {
            return false;
        }
        final String name = DeviceUtil.getName(deviceInfo, null);
        return name.equals("YubiKey Bio - Multi-protocol Edition") ||
                name.equals("YubiKey C Bio - Multi-protocol Edition");
    }
}

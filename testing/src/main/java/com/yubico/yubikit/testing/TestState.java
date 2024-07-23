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

import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.ApplicationSession;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.oath.OathSession;
import com.yubico.yubikit.openpgp.OpenPgpSession;
import com.yubico.yubikit.piv.PivSession;

import java.io.IOException;

import javax.annotation.Nullable;

public class TestState {

    public static class Builder<T extends Builder<T>> {
        final protected YubiKeyDevice device;
        @Nullable
        private Byte scpKid = null;
        @Nullable
        private ReconnectDeviceCallback reconnectDeviceCallback = null;

        public Builder(YubiKeyDevice device) {
            this.device = device;
        }

        public T scpKid(@Nullable Byte scpKid) {
            this.scpKid = scpKid;
            //noinspection unchecked
            return (T) this;
        }

        public T reconnectDeviceCallback(@Nullable ReconnectDeviceCallback reconnectDeviceCallback) {
            this.reconnectDeviceCallback = reconnectDeviceCallback;
            //noinspection unchecked
            return (T) this;
        }

        public TestState build() throws Throwable {
            return new TestState(this);
        }
    }

    protected YubiKeyDevice currentDevice;
    protected ScpParameters scpParameters;
    @Nullable
    public final Byte scpKid;
    @Nullable
    private final ReconnectDeviceCallback reconnectDeviceCallback;
    private final boolean isUsbTransport;

    protected TestState(Builder<?> builder) {
        this.currentDevice = builder.device;
        this.scpKid = builder.scpKid;
        this.scpParameters = new ScpParameters(builder.device, this.scpKid);
        this.reconnectDeviceCallback = builder.reconnectDeviceCallback;
        this.isUsbTransport = builder.device.getTransport() == Transport.USB;
    }

    public boolean isUsbTransport() {
        return isUsbTransport;
    }

    @SuppressWarnings("unused")
    public interface DeviceCallback {
        void invoke() throws Throwable;
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

    public interface StatefulSessionCallbackT<T extends ApplicationSession<T>, S extends TestState, R> {
        R invoke(T session, S state) throws Throwable;
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

    // PIV helpers
    public <T extends TestState> void withPiv(StatefulSessionCallback<PivSession, T> callback)
            throws Throwable {
        try (SmartCardConnection connection = openSmartCardConnection()) {
            final PivSession piv = getPivSession(connection, scpParameters);
            assumeTrue("No PIV support", piv != null);
            //noinspection unchecked
            callback.invoke(piv, (T) this);
        }
        reconnect();
    }

    @Nullable
    protected PivSession getPivSession(SmartCardConnection connection, ScpParameters scpParameters)
            throws IOException {
        try {
            return new PivSession(connection, scpParameters.getKeyParams());
        } catch (ApplicationNotAvailableException | ApduException ignored) {
            // no PIV support
        }
        return null;
    }

    // CTAP2 helpers
    public <T extends TestState> void withCtap2(StatefulSessionCallback<Ctap2Session, T> callback)
            throws Throwable {
        try (YubiKeyConnection connection = openConnection()) {
            final Ctap2Session ctap2 = getCtap2Session(connection);
            assumeTrue("No CTAP2 support", ctap2 != null);
            //noinspection unchecked
            callback.invoke(ctap2, (T) this);
        }
        reconnect();
    }

    @Nullable
    protected Ctap2Session getCtap2Session(YubiKeyConnection connection)
            throws IOException, CommandException {
        return (connection instanceof FidoConnection)
                ? new Ctap2Session((FidoConnection) connection)
                : connection instanceof SmartCardConnection
                ? new Ctap2Session((SmartCardConnection) connection)
                : null;
    }

    // OATH helpers
    public void withOath(SessionCallback<OathSession> callback) throws Throwable {
        try (SmartCardConnection connection = openSmartCardConnection()) {
            callback.invoke(getOathSession(connection, scpParameters));
        }
        reconnect();
    }

    public <T extends TestState> void withOath(StatefulSessionCallback<OathSession, T> callback)
            throws Throwable {
        try (SmartCardConnection connection = openSmartCardConnection()) {
            //noinspection unchecked
            callback.invoke(getOathSession(connection, scpParameters), (T) this);
        }
        reconnect();
    }

    @Nullable
    private OathSession getOathSession(SmartCardConnection connection, ScpParameters scpParameters)
            throws IOException {
        try {
            return new OathSession(connection, scpParameters.getKeyParams());
        } catch (ApplicationNotAvailableException ignored) {
            // no OATH support
        }
        return null;
    }

    // OpenPGP helpers
    public <T extends TestState> void withOpenPgp(StatefulSessionCallback<OpenPgpSession, T> callback)
            throws Throwable {
        try (SmartCardConnection connection = openSmartCardConnection()) {
            //noinspection unchecked
            callback.invoke(getOpenPgpSession(connection, scpParameters), (T) this);
        }
        reconnect();
    }

    @Nullable
    protected OpenPgpSession getOpenPgpSession(SmartCardConnection connection, ScpParameters scpParameters)
            throws IOException, CommandException {
        try {
            return new OpenPgpSession(connection, scpParameters.getKeyParams());
        } catch (ApplicationNotAvailableException ignored) {
            // no OpenPgp support
        }
        return null;
    }

    // device helper
    public <T extends TestState> void withDeviceCallback(StatefulDeviceCallback<T> callback)
            throws Throwable {
        //noinspection unchecked
        callback.invoke((T) this);
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
        DeviceInfo deviceInfo = null;
        try (YubiKeyConnection connection = openConnection()) {
            ManagementSession managementSession = getManagementSession(connection, null);
            deviceInfo = managementSession.getDeviceInfo();
        } catch (IOException | CommandException ignored) {

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
}

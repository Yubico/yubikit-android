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

import java.io.IOException;

public class TestUtils {

    public static boolean isFipsCapable(DeviceInfo deviceInfo, Capability capability) {
        return deviceInfo != null &&
                (deviceInfo.getFipsCapable() & capability.bit) == capability.bit;
    }

    public static boolean isFipsCapable(YubiKeyDevice device, Capability capability) {
        return isFipsCapable(TestUtils.getDeviceInfo(device), capability);
    }

    public static boolean isFipsApproved(YubiKeyDevice device, Capability capability) {
        return isFipsApproved(TestUtils.getDeviceInfo(device), capability);
    }

    public static boolean isFipsApproved(DeviceInfo deviceInfo, Capability capability) {
        return deviceInfo != null &&
                (deviceInfo.getFipsApproved() & capability.bit) == capability.bit;
    }

    public static DeviceInfo getDeviceInfo(YubiKeyDevice device) {
        DeviceInfo deviceInfo = null;
        try (YubiKeyConnection connection = openConnection(device)) {
            ManagementSession managementSession = getManagementSession(connection, null);
            deviceInfo = managementSession.getDeviceInfo();
        } catch (IOException | CommandException ignored) {

        }

        return deviceInfo;
    }

    static ManagementSession getManagementSession(YubiKeyConnection connection, ScpParameters scpParameters)
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

    interface Callback<T extends ApplicationSession<T>> {
        void invoke(T session) throws Throwable;
    }

    public static YubiKeyConnection openConnection(YubiKeyDevice device) throws IOException {
        if (device.supportsConnection(FidoConnection.class)) {
            return device.openConnection(FidoConnection.class);
        }
        if (device.supportsConnection(SmartCardConnection.class)) {
            return device.openConnection(SmartCardConnection.class);
        }
        throw new IllegalArgumentException("Device does not support FIDO or SmartCard connection");
    }
}

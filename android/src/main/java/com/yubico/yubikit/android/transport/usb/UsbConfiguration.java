/*
 * Copyright (C) 2020 Yubico.
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

/**
 * Additional configurations for USB discovery management
 */
public class UsbConfiguration {

    // whether to prompt permissions when application needs them
    private boolean handlePermissions = true;

    // whether manager should discover only devices with Yubico as vendor
    private boolean filterYubicoDevices = true;

    boolean isHandlePermissions() {
        return handlePermissions;
    }

    boolean isFilterYubicoDevices() {
        return filterYubicoDevices;
    }

    /**
     * Set YubiKitManager to show dialog for permissions on USB connection
     *
     * @param handlePermissions true to show dialog for permissions
     *                          otherwise it's delegated on user to make sure that application
     *                          has permissions to communicate with device
     * @return the UsbConfiguration, for chaining
     */
    public UsbConfiguration handlePermissions(boolean handlePermissions) {
        this.handlePermissions = handlePermissions;
        return this;
    }

    /**
     * Allow discovery of non-Yubico devices
     *
     * @param filterYubicoDevices true to only handle Yubico devices
     * @return the UsbConfiguration, for chaining
     */
    public UsbConfiguration filterYubicoDevices(boolean filterYubicoDevices) {
        this.filterYubicoDevices = filterYubicoDevices;
        return this;
    }
}

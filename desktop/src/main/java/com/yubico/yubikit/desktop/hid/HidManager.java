/*
 * Copyright (C) 2022,2024 Yubico.
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

import com.yubico.yubikit.core.internal.Logger;

import org.hid4java.HidServices;
import org.hid4java.HidServicesListener;
import org.hid4java.event.HidServicesEvent;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nullable;

public class HidManager {

    private static final int YUBICO_VENDOR_ID = 0x1050;
    private static final int HID_USAGE_PAGE_OTP = 0x0001;
    private static final int HID_USAGE_PAGE_FIDO = 0xf1d0;


    private final HidServices services;

    private final org.slf4j.Logger logger = LoggerFactory.getLogger(HidManager.class);

    public HidManager() {
        services = org.hid4java.HidManager.getHidServices();
    }

    public List<HidDevice> getHidDevices(int vendorId, @Nullable Integer usagePage) {
        List<HidDevice> yubikeys = new ArrayList<>();
        for (org.hid4java.HidDevice device: services.getAttachedHidDevices()) {
            if(device.getVendorId() == vendorId &&
                    (usagePage != null && (device.getUsagePage() & 0xffff) == usagePage)) {
                yubikeys.add(new HidDevice(device));
            }
        }
        return yubikeys;
    }

    public List<HidDevice> getOtpDevices() {
        return getHidDevices(YUBICO_VENDOR_ID, HID_USAGE_PAGE_OTP);
    }

    public List<HidDevice> getFidoDevices() {
        return getHidDevices(YUBICO_VENDOR_ID, HID_USAGE_PAGE_FIDO);
    }

    public void setListener(HidSessionListener listener) {
        services.addHidServicesListener(new HidServicesListener() {
            @Override
            public void hidDeviceAttached(HidServicesEvent event) {
                Logger.debug(logger, "HID attached: {}", event);
                listener.onSessionReceived(new HidDevice(event.getHidDevice()));
            }

            @Override
            public void hidDeviceDetached(HidServicesEvent event) {
                Logger.debug(logger, "HID removed: {}", event);
            }

            @Override
            public void hidFailure(HidServicesEvent event) {
                Logger.debug(logger, "HID failure: {}", event);
            }

            @Override
            public void hidDataReceived(HidServicesEvent event) {
                Logger.debug(logger, "HID Data received: {}", event);
            }
        });
    }
}

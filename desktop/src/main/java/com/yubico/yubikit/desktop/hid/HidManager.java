/*
 * Copyright (C) 2022 Yubico.
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

import com.yubico.yubikit.core.Logger;

import org.hid4java.HidServices;
import org.hid4java.HidServicesListener;
import org.hid4java.event.HidServicesEvent;

import java.util.ArrayList;
import java.util.List;

public class HidManager {

    private final HidServices services;

    public HidManager() {
        services = org.hid4java.HidManager.getHidServices();
    }

    public List<HidDevice> getDevices() {
        List<HidDevice> yubikeys = new ArrayList<>();
        for (org.hid4java.HidDevice device: services.getAttachedHidDevices()) {
            if(device.getProductId() == 0x1050) {
                yubikeys.add(new HidDevice(device));
            }
        }
        return yubikeys;
    }

    public List<HidDevice> getOtpDevices() {
        List<HidDevice> yubikeys = new ArrayList<>();
        for (org.hid4java.HidDevice device: services.getAttachedHidDevices()) {
            if(device.getVendorId() == 0x1050 && (device.getUsagePage() & 0xffff) == 1) {
                yubikeys.add(new HidDevice(device));
            }
        }
        return yubikeys;
    }

    public List<HidDevice> getFidoDevices() {
        List<HidDevice> yubikeys = new ArrayList<>();
        for (org.hid4java.HidDevice device: services.getAttachedHidDevices()) {
            if(device.getVendorId() == 0x1050 && (device.getUsagePage() & 0xffff) == 0xf1d0) {
                yubikeys.add(new HidDevice(device));
            }
        }
        return yubikeys;
    }

    public void setListener(HidSessionListener listener) {
        services.addHidServicesListener(new HidServicesListener() {
            @Override
            public void hidDeviceAttached(HidServicesEvent event) {
                Logger.d("HID attached: " + event);
                listener.onSessionReceived(new HidDevice(event.getHidDevice()));
            }

            @Override
            public void hidDeviceDetached(HidServicesEvent event) {
                Logger.d("HID removed: " + event);
            }

            @Override
            public void hidFailure(HidServicesEvent event) {
                Logger.d("HID failure: " + event);
            }
        });
    }
}

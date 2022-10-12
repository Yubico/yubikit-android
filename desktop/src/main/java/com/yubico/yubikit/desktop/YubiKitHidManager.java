package com.yubico.yubikit.desktop;

import com.yubico.yubikit.core.Logger;

import org.hid4java.HidManager;
import org.hid4java.HidServices;
import org.hid4java.HidServicesListener;
import org.hid4java.event.HidServicesEvent;

public class YubiKitHidManager {

    private final HidServices services;

    public YubiKitHidManager() {
        services = HidManager.getHidServices();
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

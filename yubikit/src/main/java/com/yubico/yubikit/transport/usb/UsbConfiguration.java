package com.yubico.yubikit.transport.usb;

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
     * @param handlePermissions true to show dialog for permissions
     *                          otherwise it's delegated on user to make sure that application
     *                          has permissions to communicate with device
     */
    public UsbConfiguration setHandlePermissions(boolean handlePermissions) {
        this.handlePermissions = handlePermissions;
        return this;
    }

    public void setFilterYubicoDevices(boolean filterYubicoDevices) {
        this.filterYubicoDevices = filterYubicoDevices;
    }
}

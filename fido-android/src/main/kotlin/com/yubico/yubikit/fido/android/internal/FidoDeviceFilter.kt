/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit.fido.android.internal

import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import com.yubico.yubikit.android.transport.usb.DeviceFilter

internal class FidoDeviceFilter : DeviceFilter() {
    /**
     * Matches any vendor and product ID combination.
     *
     * @param vendorId the USB vendor ID
     * @param productId the USB product ID
     * @return always true, as all IDs are accepted
     */
    override fun checkVendorProductIds(
        vendorId: Int,
        productId: Int,
    ): Boolean {
        // match all vendors and products
        return true
    }

    override fun checkUsbDevice(
        manager: UsbManager,
        usbDevice: UsbDevice,
    ): Boolean {
        return true
    }
}

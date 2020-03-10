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

package com.yubico.yubikit.transport.usb;

import androidx.annotation.NonNull;

public interface UsbSessionListener {
    /**
     * Invoked when detected inserted device after usb discovery started
     * @param session usb session that associated with plugged in device
     * @param hasPermission true if device has required permissions granted by user
     */
    void onSessionReceived(@NonNull final UsbSession session, boolean hasPermission);

    /**
     * Invoked when detected removal/ejection of usb device after usb discovery started
     * @param session usb session that will become inactive
     */
    void onSessionRemoved(@NonNull final UsbSession session);

    /**
     * If discovery was started with handling permissions than user will be prompted with UI
     * dialog to ask for necessary permissions to communicate with device
     * @param session usb session for which user had permissions prompt
     * @param isGranted true if user selected to grant permissions, otherwise false
     */
    void onRequestPermissionsResult(@NonNull final UsbSession session, boolean isGranted);
}

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
package com.yubico.yubikit.android.ui;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.KeyEvent;
import android.widget.TextView;
import com.yubico.yubikit.android.R;
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice;
import com.yubico.yubikit.android.transport.usb.UsbConfiguration;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyListener;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice;
import com.yubico.yubikit.core.CommandState;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.util.NdefUtils;
import com.yubico.yubikit.core.util.Pair;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;

/**
 * An Activity to prompt the user for a YubiKey to retrieve an OTP from a YubiOTP slot.
 */
public class OtpActivity extends YubiKeyPromptActivity {
    public static final String EXTRA_OTP = "otp";
    public static final String EXTRA_ERROR = "error";

    private OtpKeyListener keyListener;

    private int usbSessionCounter = 0;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        getIntent().putExtra(ARG_ACTION_CLASS, YubiKeyNdefAction.class);
        getIntent().putExtra(ARG_ALLOW_USB, false);  // Custom USB handling for keyboard.

        super.onCreate(savedInstanceState);

        getYubiKitManager().startUsbDiscovery(new UsbConfiguration().handlePermissions(false), new UsbYubiKeyListener() {
            @Override
            public void onDeviceAttached(@Nonnull UsbYubiKeyDevice device, boolean hasPermission) {
                usbSessionCounter++;
                runOnUiThread(() -> helpTextView.setText(R.string.yubikit_otp_touch));
            }

            @Override
            public void onDeviceRemoved(@Nonnull UsbYubiKeyDevice device) {
                usbSessionCounter--;
                if (usbSessionCounter == 0) {
                    runOnUiThread(() -> helpTextView.setText(isNfcEnabled() ? R.string.yubikit_prompt_plug_in_or_tap : R.string.yubikit_prompt_plug_in));
                }
            }

            @Override
            public void onRequestPermissionsResult(@Nonnull UsbYubiKeyDevice device, boolean isGranted) {
                // We don't need permissions to handle YubiOTP
            }
        });

        keyListener = new OtpKeyListener(new OtpKeyListener.OtpListener() {
            @Override
            public void onCaptureStarted() {
                helpTextView.setText(R.string.yubikit_prompt_wait);
            }

            @Override
            public void onCaptureComplete(String capture) {
                Intent intent = new Intent();
                intent.putExtra(EXTRA_OTP, capture);
                setResult(Activity.RESULT_OK, intent);
                finish();
            }
        });
    }

    @Override
    public boolean onKeyUp(int keyCode, KeyEvent event) {
        return keyListener.onKeyEvent(event);
    }

    static class YubiKeyNdefAction extends YubiKeyPromptAction {
        @Nullable
        @Override
        Pair<Integer, Intent> onYubiKey(YubiKeyDevice device, Bundle extras, CommandState commandState) {
            if (device instanceof NfcYubiKeyDevice) {
                Intent intent = new Intent();
                try {
                    String credential = NdefUtils.getNdefPayload(((NfcYubiKeyDevice) device).readNdef());
                    intent.putExtra(EXTRA_OTP, credential);
                    return new Pair<>(Activity.RESULT_OK, intent);
                } catch (IOException e) {
                    intent.putExtra(EXTRA_ERROR, e);
                    return new Pair<>(Activity.RESULT_FIRST_USER, intent);
                }
            }
            return null;
        }
    }
}

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

package com.yubico.yubikit.otp;

import android.os.Handler;
import android.os.Looper;
import android.util.SparseArray;
import android.view.InputDevice;
import android.view.KeyEvent;
import android.view.View;

import java.util.Timer;

/**
 * Listens for keyboard events from yubico devices
 * View that has this listener must be clickable
 */
public class KeyListener implements View.OnKeyListener {
    private final static int YUBICO_VID = 0x1050;
    private final static int DEFAULT_KEY_DELAY_MS = 1000;
    private Timer timer = new Timer();
    private final OtpListener listener;
    private final SparseArray<StringBuilder> inputBuffers = new SparseArray<>();
    private final Handler handler = new Handler(Looper.getMainLooper());

    /**
     * Creates instance of {@link KeyListener}
     * @param listener the listener that will be invoked upon detection of OTP code from YubiKey emitting button
     */
    KeyListener(OtpListener listener) {
        this.listener = listener;
    }

    @Override
    public boolean onKey(View v, int keyCode, KeyEvent event) {
        InputDevice device = event.getDevice();
        if (device.getVendorId() != YUBICO_VID) {
            // do not handle anything that not from yubikey
            return false;
        }

        if (event.getAction() == KeyEvent.ACTION_UP) {
            // use id of keyboard device to distinguish current input device
            // in case of multiple keys inserted
            final int deviceId = event.getDeviceId();
            final StringBuilder otpBuffer = inputBuffers.get(deviceId, new StringBuilder());
            if (event.getKeyCode() == KeyEvent.KEYCODE_ENTER || event.getKeyCode() == KeyEvent.KEYCODE_NUMPAD_ENTER) {
                // Carriage return seen. Assume this is the end of the OTP credential and notify immediately.
                listener.onOtpReceived(otpBuffer.toString());
                inputBuffers.delete(deviceId);
            } else {
                if (otpBuffer.length() == 0) {
                    // in case if we never get keycode enter (which is pretty generic scenario) we set timer for 1 sec
                    // upon expiration we assume that we have no more input from key
                    handler.postDelayed(new InputTimerTask(deviceId), DEFAULT_KEY_DELAY_MS);
                }
                otpBuffer.append((char) event.getUnicodeChar());
                inputBuffers.put(deviceId, otpBuffer);
            }
        }
        return true;
    }

    /**
     * Runnable that will be invoked on UI thread with some delay
     * Returns result with listener if it wasn't sent to user yet
     */
    private class InputTimerTask implements Runnable {
        private final int deviceId;
        private InputTimerTask(int deviceId) {
            this.deviceId = deviceId;
        }

        @Override
        public void run() {
            final StringBuilder otpBuffer = inputBuffers.get(deviceId, new StringBuilder());
            // if buffer is empty it means that we sent it to user already, avoid double invocation
            if (otpBuffer.length() > 0) {
                listener.onOtpReceived(otpBuffer.toString());
                inputBuffers.delete(deviceId);
            }
        }
    }
    /**
     * Listener that is invoked upon receiving of Yubi OTP
     */
    interface OtpListener {
        void onOtpReceived(String otpCredential);
    }
}
